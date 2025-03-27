import json
import argparse
from graphviz import Digraph

def generate_sbom_graph(sbom_file, output_file):
    with open(sbom_file, 'r') as f:
        sbom = json.load(f)

    dot = Digraph(comment='SBOM Components Graph')
    dot.attr(rankdir='LR', size='12,8', nodesep='0.5')
    dot.attr('node', shape='box', style='rounded,filled', fillcolor='lightgrey')
    dot.attr('edge', arrowhead='vee', arrowsize='0.5')

    libraries = {}
    applications = {}

    for component in sbom.get('components', []):
        if component['type'] == 'library':
            libraries[component['bom-ref']] = {
                'name': component['name'],
                'version': component.get('version', '?')
            }
        elif component['type'] == 'application':
            applications[component['bom-ref']] = {
                'name': component['name'],
                'version': component.get('version', '?')
            }

    for app_id, app_data in applications.items():
        label = f"{app_data['name']}\n{app_data['version']}"
        dot.node(app_id, label, shape='ellipse', fillcolor='lightblue')

    for lib_id, lib_data in libraries.items():
        label = f"{lib_data['name']}\nversion:{lib_data['version']}"
        dot.node(lib_id, label)

    for dependency in sbom.get('dependencies', []):
        ref = dependency['ref']
        depends_on = dependency.get('dependsOn', [])

        for dep in depends_on:
            if dep in libraries or dep in applications:
                dot.edge(ref, dep)

    dot.render(output_file, format='svg', cleanup=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Draw the graph of dependencies from given cyclondedx json file"
    )
    parser.add_argument("-i", required=True,
                            help="path to sbom file")
    parser.add_argument("-o", required=True,
                            help="name of out file§")
    args = parser.parse_args()
    generate_sbom_graph(args.i, args.o)
