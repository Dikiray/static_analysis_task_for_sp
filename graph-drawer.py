import json
import argparse
from graphviz import Digraph

def generate_sbom_graph(sbom_file, output_file):
    with open(sbom_file, 'r') as f:
        sbom = json.load(f)

    dot = Digraph(comment='SBOM Components Graph')
    dot.attr(rankdir='TB', size='12,8', nodesep='0.5')
    dot.attr('node', shape='box', style='rounded,filled', fillcolor='lightgrey')
    dot.attr('edge', arrowhead='vee', arrowsize='0.5')

    all_components = {}
    parent_components = {}

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

    for component_id, component_data in all_components.items():
        if component_data['parent'] is None:
            if component_id in parent_components:
                label = f"{component_data['name']}\n{component_data['version']}"
                dot.node(component_id, label, shape='folder', fillcolor='lightyellow')
            else:
                label = f"{component_data['name']}\n{component_data['version']}"
                dot.node(component_id, label)
        else:
            parent_name = all_components[component_data['parent']]['name']
            label = f"{parent_name}/{component_data['name']}\n{component_data['version']}"
            dot.node(component_id, label, shape='box', fillcolor='#f0f0f0')

    for parent_id in parent_components:
        for child_id in all_components[parent_id]['children']:
            dot.edge(parent_id, child_id, style='dashed', color='gray')

    for dependency in sbom.get('dependencies', []):
        ref = dependency['ref']
        depends_on = dependency.get('dependsOn', [])

        for dep in depends_on:
            if dep in all_components:
                if (ref == all_components.get(dep, {}).get('parent')) or \
                   (dep == all_components.get(ref, {}).get('parent')):
                    continue
                dot.edge(ref, dep)

    dot.render(output_file, format='svg', cleanup=True)
    print(f"Graph saved as {output_file}.svg")

def main():
    parser = argparse.ArgumentParser(description='Generate SBOM component graph from CycloneDX JSON file')
    parser.add_argument('-i', help='Path to the CycloneDX JSON SBOM file')
    parser.add_argument('-o', default='sbom_graph',
                       help='Output file name (without extension)')

    args = parser.parse_args()

    generate_sbom_graph(args.i, args.o)

if __name__ == "__main__":
    main()
