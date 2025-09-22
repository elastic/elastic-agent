"""
EDOT Collector Documentation Generation Tools

This module provides tools for automatically generating and updating EDOT Collector documentation
based on local data sources. It includes functionality for:

- Component table generation from local Elastic Agent go.mod files
- OCB (OpenTelemetry Collector Builder) file generation

The scripts read data from local Elastic Agent repository files and generate documentation
using Jinja2 templates.
"""

from jinja2 import Environment, FileSystemLoader
from collections import defaultdict
import yaml
import re
from pathlib import Path
import subprocess
import os
import tempfile

TABLE_TAG = 'edot-collector-components-table'
DEPS_TAG = 'edot-collector-components-ocb'

EDOT_COLLECTOR_DIR = '../../../docs/reference/edot-collector'
TEMPLATE_COLLECTOR_COMPONENTS_TABLE = 'templates/components-table.jinja2'
TEMPLATE_COLLECTOR_OCB_FILE = 'templates/ocb.jinja2'
COMPONENT_DOCS_YAML = '../../../docs/reference/edot-collector/component-docs.yml'


def read_file_from_git_tag(file_path, tag):
    """Read a file from a specific Git tag"""
    try:
        result = subprocess.run(
            ['git', 'show', f'{tag}:{file_path}'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error reading {file_path} from tag {tag}: {e}")
        return None

def get_latest_version():
    """Get the latest version from environment variable or discover from Git tags"""
    # Check if we have a version specified via environment variable (from GitHub Actions)
    env_version = os.environ.get('LATEST_VERSION')
    if env_version:
        return env_version.lstrip('v')  # Remove 'v' prefix if present
    
    # Discover latest version from Git tags
    try:
        cmd = "git tag --list | grep -E '^v[0-9]+\\.[0-9]+\\.[0-9]+$' | sort -V | tail -1"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        latest_tag = result.stdout.strip()
        if latest_tag:
            return latest_tag.lstrip('v')
        else:
            raise ValueError("No semantic version tags found")
    except subprocess.CalledProcessError as e:
        raise ValueError(f"Failed to discover latest version from Git tags: {e}")

def get_core_components(version='main'):
    """Read and parse the core-components.yaml file to determine support status"""
    latest_version = get_latest_version()
    version_tag = f"v{latest_version}"
    
    # Always read from Git tag
    core_components_path = 'internal/pkg/otel/core-components.yaml'
    print(f"Reading core components from tag {version_tag}: {core_components_path}")
    content = read_file_from_git_tag(core_components_path, version_tag)
    if content is None:
        raise ValueError(f"Could not read core components file from tag {version_tag}. Ensure the tag exists and contains the file.")
        
    try:
        data = yaml.safe_load(content)
        return data.get('components', [])
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing core-components.yaml from tag {version_tag}: {e}")

def dep_to_component(dep):
    url = dep[:dep.rfind(' v')].strip()
    html_url = url
    repo_link = '[OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib)'
    if url.startswith('github.com/'):
        pattern = r'github.com/(?P<org>[^/]*)/(?P<repo>[^/]*)/(?P<comp_type>[^/]*)/(?P<comp_name>.*)'
        match = re.search(pattern, url)
        if match:
            html_url = f'https://github.com/{match.group("org")}/{match.group("repo")}/tree/main/{match.group("comp_type")}/{match.group("comp_name")}'
            if match.group("repo") == 'opentelemetry-collector-components':
                repo_link = '[Elastic Repo](https://github.com/elastic/opentelemetry-collector-components)'
    elif url.startswith('go.opentelemetry.io/collector'):
        pattern = r'go.opentelemetry.io/collector/(?P<comp_type>[^/]*)/(?P<comp_name>.*)'
        match = re.search(pattern, url)
        if match:
            html_url = f'https://github.com/open-telemetry/opentelemetry-collector/tree/main/{match.group("comp_type")}/{match.group("comp_name")}'
            repo_link = '[OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector)'
        
    comp = {
        'name': dep[(dep.rfind('/')+1):(dep.rfind(' ')+1)],
        'version': dep[(dep.rfind(' ')+1):],
        'html_url': html_url,
        'repo_link': repo_link,
        'dep': dep.strip()
    }
    return comp
    
def get_otel_col_upstream_version():
    """Read the OpenTelemetry Collector version from go.mod file"""
    latest_version = get_latest_version()
    version_tag = f"v{latest_version}"
    
    # Always read from Git tag
    go_mod_path = 'go.mod'
    print(f"Reading go.mod from tag {version_tag}: {go_mod_path}")
    content = read_file_from_git_tag(go_mod_path, version_tag)
    if content is None:
        raise ValueError(f"Could not read go.mod from tag {version_tag}. Ensure the tag exists and contains the file.")
    
    lines = content.splitlines()
    for line in lines:
        if 'go.opentelemetry.io/collector/otelcol ' in line:
            return line[(line.rfind('v')+1):]
    
    raise ValueError(f"Could not find OpenTelemetry Collector version in go.mod from tag {version_tag}")
            
def get_collector_version():
    """Get the collector version from latest release tag"""
    return get_latest_version()
    
def get_otel_components(version='main', component_docs_mapping=None):
    """Read OpenTelemetry components from go.mod file"""
    latest_version = get_latest_version()
    version_tag = f"v{latest_version}"
    
    # Always read from Git tag
    go_mod_path = 'go.mod'
    print(f"Reading go.mod from tag {version_tag}: {go_mod_path}")
    elastic_agent_go_mod = read_file_from_git_tag(go_mod_path, version_tag)
    if elastic_agent_go_mod is None:
        raise ValueError(f"Could not read go.mod from tag {version_tag}. Ensure the tag exists and contains the file.")

    # Get the list of core components
    core_components = get_core_components(version)
    print(f"Found {len(core_components)} core components")

    lines = elastic_agent_go_mod.splitlines()
    components_type = ['receiver', 'connector', 'processor', 'exporter', 'extension', 'provider']
    otel_deps = [line for line in lines if (not line.endswith('// indirect') and ("=>" not in line) and (any(f'/{comp}/' in line for comp in components_type)))]
    otel_components = list(map(dep_to_component, otel_deps))
    
    # Add support status and documentation links to each component
    for comp in otel_components:
        # Extract the component name without the suffix (e.g., 'filelogreceiver' from 'filelogreceiver ')
        comp_name = comp['name'].strip()
        # Check if this component is in the core components list
        if comp_name in core_components:
            comp['support_status'] = '[Core]'
        else:
            comp['support_status'] = '[Extended]'
            
        # Add documentation link if available
        if component_docs_mapping and comp_name in component_docs_mapping:
            comp['doc_link'] = component_docs_mapping[comp_name]['doc_path']
        else:
            comp['doc_link'] = None

    components_grouped = defaultdict(list)

    for comp in otel_components:
        for substring in components_type:
            if f'/{substring}/' in comp['dep']:
                components_grouped[f'{substring.capitalize()}s'].append(comp)
                break  # Assumes each string matches only one group

    components_grouped = dict(components_grouped)

    for key, group in components_grouped.items():
        components_grouped[key] = sorted(group, key=lambda comp: comp['name'])
        
    return components_grouped

def find_files_with_substring(directory, substring):
    matching_files = []
    # Compile the substring into a regular expression for case-insensitive search
    pattern = re.compile(re.escape(substring), re.IGNORECASE)
    # Use pathlib to iterate over all files in the directory and subdirectories
    for file_path in Path(directory).rglob('*'):
        if file_path.is_file():
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    if pattern.search(content):
                        matching_files.append(str(file_path))
            except (UnicodeDecodeError, PermissionError) as e:
                # Skip files that can't be read due to encoding issues or permission errors
                print(f"Skipping {file_path}: {e}")
    return matching_files

def render_markdown(data, template):
    # Set up the Jinja2 environment
    env = Environment(loader=FileSystemLoader('.'))

    # Load the template
    template = env.get_template(template)

    # Define the data to pass to the template

    return template.render(data)

def render_components_into_file(dir, data, template, tag):    
    output = render_markdown(data, template)
    start_tag = f'% start:{tag}'
    end_tag = f'% end:{tag}'
    
    filesPaths = find_files_with_substring(dir, start_tag)
    
    for filePath in filesPaths:
        with open(filePath, 'r', encoding='utf-8') as file:
            content = file.read()
            
        pattern = start_tag + r'.*?' + end_tag
        new_content = f'{start_tag}\n{output}\n{end_tag}'
        updated_content = re.sub(pattern, new_content, content, flags=re.DOTALL)

        with open(filePath, 'w', encoding='utf-8') as file:
            file.write(updated_content)   

def check_markdown_generation(dir, data, template, tag):
    output = render_markdown(data, template)
    start_tag = f'% start:{tag}'
    end_tag = f'% end:{tag}'
    
    filesPaths = find_files_with_substring(dir, start_tag)
    
    for filePath in filesPaths:
        with open(filePath, 'r', encoding='utf-8') as file:
            content = file.read()
        
        pattern = start_tag + r'(.*?)' + end_tag

        matches = re.findall(pattern, content, re.DOTALL)
        
        for match in matches:
            if match.strip() != output.strip():
                print(f'Warning: Generated markdown is outdated in file {filePath}! Regenerate markdown by running `make generate`!')
                return False;
            
    return True;

def get_component_docs_mapping(source_file):
    """Load component documentation mapping from YAML file"""
    try:
        with open(source_file, 'r') as file:
            data = yaml.safe_load(file)
            return data.get('components', {})
    except FileNotFoundError:
        print(f"Component docs mapping file not found: {source_file}")
        return {}
    except yaml.YAMLError as exc:
        print(f"Error reading component docs YAML file: {exc}")
        return {}

def check_markdown():
    col_version = get_collector_version()
    print(f"Collector version: {col_version}")
    
    # Load component documentation mapping
    component_docs_mapping = get_component_docs_mapping(COMPONENT_DOCS_YAML)
    print(f"Loaded {len(component_docs_mapping)} component documentation mappings")
    
    # Read components from local files
    components = get_otel_components(col_version, component_docs_mapping)
    
    if components is None:
        print("Failed to read components from local files")
        return False
        
    otel_col_version = get_otel_col_upstream_version()
    data = {
        'grouped_components': components,
        'otel_col_version': otel_col_version
    }
    tables = check_markdown_generation(EDOT_COLLECTOR_DIR, data, TEMPLATE_COLLECTOR_COMPONENTS_TABLE, TABLE_TAG) 
    ocb = check_markdown_generation(EDOT_COLLECTOR_DIR, data, TEMPLATE_COLLECTOR_OCB_FILE, DEPS_TAG)
    
    return tables and ocb

def generate_markdown():
    col_version = get_collector_version()
    print(f"Collector version: {col_version}")
    
    # Load component documentation mapping
    component_docs_mapping = get_component_docs_mapping(COMPONENT_DOCS_YAML)
    print(f"Loaded {len(component_docs_mapping)} component documentation mappings")
    
    # Read components from local files
    components = get_otel_components(col_version, component_docs_mapping)
    
    if components is None:
        print("Failed to read components from local files")
        return
        
    otel_col_version = get_otel_col_upstream_version()
    data = {
        'grouped_components': components,
        'otel_col_version': otel_col_version
    }
    render_components_into_file(EDOT_COLLECTOR_DIR, data, TEMPLATE_COLLECTOR_COMPONENTS_TABLE, TABLE_TAG)
    render_components_into_file(EDOT_COLLECTOR_DIR, data, TEMPLATE_COLLECTOR_OCB_FILE, DEPS_TAG)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        check_markdown()
    else:
        generate_markdown()
