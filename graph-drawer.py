#!/usr/bin/env python3
"""
Generate a graph visualization of Software Bill of Materials (SBOM) components.

This script takes a CycloneDX JSON SBOM file as input and generates a visual
graph representation showing the relationships between components.
"""

import json
import argparse
from graphviz import Digraph


def generate_sbom_graph(sbom_file, output_file):
    """
    Generate a graph visualization from SBOM data.

    Args:
        sbom_file (str): Path to the CycloneDX JSON SBOM file
        output_file (str): Path for the output graph file (without extension)
    """
    with open(sbom_file, 'r') as f:
        sbom = json.load(f)

    dot = Digraph(comment='SBOM Components Graph')
    dot.attr(rankdir='TB', size='12,8', nodesep='0.7')
    dot.attr('node', shape='box', style='rounded,filled', fillcolor='lightgrey')
    dot.attr('edge', arrowhead='vee', arrowsize='0.7')

    all_components = {}
    parent_components = {}
    main_comp_components = set()
    main_comp_ref = None
    name = ""

    tools = sbom.get('metadata', {}).get('tools', {}).get('components', [])
    for tool in tools:
        if tool.get('name').endswith("FOLDER"):
            name = tool.get('name')
            main_comp_ref = tool.get('bom-ref')
            break

    for component in sbom.get('components', []):
        component_id = component['bom-ref']
        all_components[component_id] = {
            'name': component['name'],
            'version': component.get('version', '?'),
            'type': component['type'],
            'parent': None,
            'children': []
        }

        if 'components' in component:
            parent_components[component_id] = all_components[component_id]
            for child in component['components']:
                child_id = child['bom-ref']
                all_components[child_id] = {
                    'name': child['name'],
                    'version': child.get('version', '?'),
                    'type': child['type'],
                    'parent': component_id,
                    'children': []
                }
                all_components[component_id]['children'].append(child_id)
                main_comp_components.add(child_id)

    if main_comp_ref:
        dot.node(main_comp_ref, name, shape='folder', fillcolor='lightblue')

    for component_id, component_data in all_components.items():
        if component_data['parent'] is None:
            label = f"{component_data['name']}\n{component_data['version']}"
            if component_id in parent_components:
                dot.node(component_id, label, shape='folder',
                        fillcolor='lightyellow')
            else:
                dot.node(component_id, label)
        else:
            parent_name = all_components[component_data['parent']]['name']
            label = (f"{parent_name}/{component_data['name']}\n"
                    f"{component_data['version']}")
            dot.node(component_id, label, shape='box', fillcolor='#f0f0f0')

    if main_comp_ref:
        for component_id in all_components:
            if component_id not in main_comp_components:
                dot.edge(component_id, main_comp_ref, style='dashed',
                        color='blue')

    for parent_id in parent_components:
        for child_id in all_components[parent_id]['children']:
            dot.edge(child_id, parent_id, style='dashed', color='gray')

    for dependency in sbom.get('dependencies', []):
        ref = dependency['ref']
        depends_on = dependency.get('dependsOn', [])

        for dep in depends_on:
            if dep in all_components:
                if ((ref == all_components.get(dep, {}).get('parent')) or
                        (dep == all_components.get(ref, {}).get('parent'))):
                    continue
                dot.edge(ref, dep)

    dot.render(output_file, format='svg', cleanup=True)
    print(f"Graph saved as {output_file}.svg")


if __name__ == "__main__":
    """Parse command line arguments and generate the SBOM graph."""
    parser = argparse.ArgumentParser(
        description='Generate a visual graph from a CycloneDX JSON SBOM file.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i sbom.json -o output_graph
  %(prog)s --input sbom.json --output dependency_graph
        """)
    
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Path to the CycloneDX JSON SBOM file'
    )
    parser.add_argument(
        '-o', '--output',
        default='sbom_graph',
        help='Output file name (without extension). Default: sbom_graph'
    )

    args = parser.parse_args()
    generate_sbom_graph(args.input, args.output)
