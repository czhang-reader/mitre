#! /usr/bin/env python3

import sys
import json

"""
Process MITRE ATT&CK data in JSON format and output a markdown file with Tactics, Techniques, and Sub-techniques.

Usage: attack_parse.py <attack_json_file> <output_md_file>

Author: Chi Zhang

Notes:
* Throughout the code, mitre_obj refers to a dict obj in the bundle's "objects" list. Each mitre_obj has a "type" field
  that indicates whether it is a tactic, technique/sub-technique, or relationship.
* A technique may belong to multiple tactics. For example: T1133 appears under both TA0001 and TA0003.
* Descriptions may contain markdowns that may interfere with the overall visual representation for title,
tactics, technique, sub-technique in the markdown output. So we enclose the description in a code block.
* Results can be manually checked against https://attack.mitre.org/
"""


class MitreBase:
    """
    Base class for Tactic, Technique, SubTechnique
    """

    def __init__(self, mitre_obj):
        self.name = mitre_obj.get("name", "")
        self.id = mitre_obj.get("id", "")
        self.description = mitre_obj.get("description", "")

        # Find MITRE ID, e.g. TA0001 (Tactic), T1078 (Technique), T1078.001 (SubTechnique)
        self.mitre_id = ""
        external_references = mitre_obj.get("external_references", [])
        for ref_obj in external_references:
            if ref_obj.get("source_name", "") == "mitre-attack":
                self.mitre_id = ref_obj.get("external_id", "")


class Tactic(MitreBase):
    """
    Tactic class
    Contains a list of Techniques
    """

    def __init__(self, mitre_obj):
        super().__init__(mitre_obj)
        self.normalized_name = self.name.lower().replace(
            " ", "-"
        )  # Normalized tacticname: e.g. "Initial Access" -> "initial-access"
        self.techniques = []

    def add_technique(self, technique):
        self.techniques.append(technique)

    def sort_by_mitre_id(self):
        self.techniques = sorted(self.techniques, key=lambda x: x.mitre_id)
        for tech in self.techniques:
            tech.sort_by_mitre_id()

    def markdown(self):
        lines = []
        lines.append(f"## {self.mitre_id} {self.name}\n")
        lines.append(f"```\n{self.description}\n```\n")
        for tech in self.techniques:
            lines.append(tech.markdown())
        return "\n".join(lines)


class Technique(MitreBase):
    """
    Technique class
    Contains a list of SubTechniques
    """

    def __init__(self, mitre_obj):
        super().__init__(mitre_obj)
        kill_chain_phases = mitre_obj.get("kill_chain_phases", [])
        self.kill_chain_names = [
            phase.get("phase_name", "") for phase in kill_chain_phases
        ]
        self.subtechniques = []

    def add_subtechnique(self, subtech):
        self.subtechniques.append(subtech)

    def sort_by_mitre_id(self):
        self.subtechniques = sorted(self.subtechniques, key=lambda x: x.mitre_id)

    def markdown(self) -> str:
        lines = []
        lines.append(f"### {self.mitre_id} {self.name}\n")
        lines.append(f"```\n{self.description}\n```\n")
        for subtech in self.subtechniques:
            lines.append(subtech.markdown())
        return "\n".join(lines)


class SubTechnique(MitreBase):
    """
    SubTechnique class
    """

    def __init__(self, mitre_obj):
        super().__init__(mitre_obj)

    def markdown(self) -> str:
        lines = []
        lines.append(f"#### {self.mitre_id} {self.name}\n")
        lines.append(f"```\n{self.description}\n```\n")
        return "\n".join(lines)


class Bundle:
    """
    Bundle class represents the entire MITRE ATT&CK data bundle
    and contains methods to process mitre objects and output markdown.
    """

    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError("bundle data must be a dict")
        if data.get("type", "") != "bundle":
            raise ValueError(f"bundle data must have 'type' field equal to 'bundle'")
        if "objects" not in data or not isinstance(data["objects"], list):
            raise ValueError("bundle data must have an 'objects' field that is a list")
        self.mitre_objects = data["objects"]
        self.tactics = []

    def process_mitre_objects(self):
        # Temp dicts used when building associations between Tactic, Technique, SubTechnique
        tactics_dict = {}  # Normalized tactic name (e.g. "initial-access") -> Tactic
        tech_dict = {}  # id -> Technique
        subtech_dict = {}  # id -> SubTechnique

        for obj in self.mitre_objects:
            if not isinstance(obj, dict):
                raise ValueError(f"object is not a dict {obj}")
            if obj.get("revoked", False):  # Skip revoked object
                continue

            obj_type = obj.get("type", "")
            if obj_type == "x-mitre-tactic":
                tactic = Tactic(obj)
                tactics_dict[tactic.normalized_name] = tactic
            elif obj_type == "attack-pattern":
                if not "x_mitre_is_subtechnique" in obj:  # Should not happen?
                    continue
                if obj.get("x_mitre_is_subtechnique"):
                    subtech = SubTechnique(obj)
                    subtech_dict[subtech.id] = subtech
                else:
                    tech = Technique(obj)
                    tech_dict[tech.id] = tech
                    # Associate technique with tactics, based on kill_chain_phases.
                    # A Technique may belong to multiple Tactics.
                    for kc_name in tech.kill_chain_names:
                        if kc_name in tactics_dict:
                            tactics_dict[kc_name].add_technique(tech)
            elif (
                obj_type == "relationship"
                and obj.get("relationship_type", "") == "subtechnique-of"
            ):
                # Associate sub-technique with technique, based on relationship object.
                # Could be moved to a separate pass in case the order of objects is not guaranteed.
                source_ref = obj.get("source_ref", "")
                target_ref = obj.get("target_ref", "")
                if source_ref in subtech_dict and target_ref in tech_dict:
                    subtech = subtech_dict[source_ref]
                    tech = tech_dict[target_ref]
                    tech.add_subtechnique(subtech)

        # Sort tactics, techniques, sub-techniques by mitre_id
        self.tactics = sorted(list(tactics_dict.values()), key=lambda x: x.mitre_id)
        for tactic in self.tactics:
            tactic.sort_by_mitre_id()

    def markdown(self) -> str:
        lines = []
        lines.append("# MITRE ATT&CK Tactics, Techniques, and Subtechniques\n")
        for tactic in self.tactics:
            lines.append(tactic.markdown())
        return "\n".join(lines)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <attack_json_file> <output_md_file>")
        return 1
    input_filename = sys.argv[1]
    output_filename = sys.argv[2]

    with open(input_filename) as in_f:
        try:
            data = json.load(in_f)
            bundle = Bundle(data)
            bundle.process_mitre_objects()
            with open(output_filename, "w") as out_f:
                out_f.write(bundle.markdown())
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from {input_filename}: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
