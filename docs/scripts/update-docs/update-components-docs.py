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
GATEWAY_9X_TAG = 'edot-gateway-9x-table'
GATEWAY_8X_TAG = 'edot-gateway-8x-table'
SAMPLES_LINKS_TAG = 'edot-samples-links'

EDOT_COLLECTOR_DIR = '../../../docs/reference/edot-collector'
TEMPLATE_COLLECTOR_COMPONENTS_TABLE = 'templates/components-table.jinja2'
TEMPLATE_COLLECTOR_OCB_FILE = 'templates/ocb.jinja2'
TEMPLATE_GATEWAY_TABLE = 'templates/gateway-table.jinja2'
TEMPLATE_SAMPLES_LINKS = 'templates/samples-links.jinja2'
COMPONENT_DOCS_YAML = '../../../docs/reference/edot-collector/component-docs.yml'
DEFAULT_CONFIG_FILE = '../../../docs/reference/edot-collector/config/default-config-standalone.md'
COMPONENTS_YAML = '../../../internal/edot/components.yml'
# Path migration configuration
# Each entry defines: new_path, old_path, and the version where the change occurred
PATH_MIGRATIONS = {
    'gomod': {
        'new': 'internal/edot/go.mod',
        'old': 'go.mod',
        'since': (9, 0, 0),  # EDOT go.mod exists from 9.0.0+
    },
    'components_yml': {
        'new': 'internal/edot/components.yml',
        'old': 'internal/pkg/otel/components.yml',
        'since': (9, 3, 0),  # Moved in PR #11821
        'exists_since': (9, 2, 1),  # File was added in v9.2.1 via PR #11040
    },
    'samples': {
        'new': 'internal/edot/samples',
        'old': 'internal/pkg/otel/samples',
        'since': (9, 3, 0),  # Moved in PR #11821
    },
    'gateway': {
        'new': 'internal/edot/samples/linux/gateway.yml',
        'old': 'internal/pkg/otel/samples/linux/gateway.yml',
        'since': (9, 3, 0),  # Moved in PR #11821
    },
}


def parse_version_tag(tag):
    """Parse a version tag into a tuple of (major, minor, patch).
    
    Args:
        tag: Git tag string (e.g., 'v9.2.2', '9.2.2', 'v9.3.0-test')
        
    Returns:
        Tuple of (major, minor, patch) integers, or None if parsing fails
    """
    # Remove 'v' prefix if present
    version_str = tag.lstrip('v')
    
    # Match semantic version pattern (allows suffixes like -test, -rc1, etc.)
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)', version_str)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return None


def resolve_path_for_tag(tag, path_type, fallback_to_file_check=True):
    """Resolve the correct file path for a given tag using semantic versioning.
    
    This is the consolidated path resolution function that handles all path
    migrations based on version comparison rather than file existence checks.
    
    Args:
        tag: Git tag to resolve path for (e.g., 'v9.2.2')
        path_type: Key from PATH_MIGRATIONS ('gomod', 'components_yml', 'samples', 'gateway')
        fallback_to_file_check: If True and version parsing fails, fall back to file existence check
        
    Returns:
        The correct path string for the tag, or None if the file doesn't exist
    """
    if path_type not in PATH_MIGRATIONS:
        raise ValueError(f"Unknown path type: {path_type}. Valid types: {list(PATH_MIGRATIONS.keys())}")
    
    config = PATH_MIGRATIONS[path_type]
    new_path = config['new']
    old_path = config['old']
    since_version = config['since']
    exists_since = config.get('exists_since')  # Optional: when file was first added
    
    version = parse_version_tag(tag)
    
    if version is not None:
        # Use semantic version comparison (fast, no subprocess)
        if version >= since_version:
            return new_path
        else:
            # Check if file exists at this version (for files added after initial release)
            if exists_since and version < exists_since:
                return None
            return old_path
    elif fallback_to_file_check:
        # Fallback to file existence check for non-standard tags
        if check_file_exists_at_tag(new_path, tag):
            return new_path
        elif check_file_exists_at_tag(old_path, tag):
            return old_path
        return None
    else:
        return None


def check_file_exists_at_tag(file_path, tag):
    """Check if a file exists at a specific Git tag.
    
    Note: This is slower than version-based resolution. Use resolve_path_for_tag()
    when possible, which uses semantic versioning for faster lookups.
    """
    try:
        subprocess.run(
            ['git', 'cat-file', '-e', f'{tag}:{file_path}'],
            capture_output=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


# Convenience functions that use the consolidated resolver
def get_gomod_path_for_tag(tag):
    """Get the correct go.mod path for a tag."""
    path = resolve_path_for_tag(tag, 'gomod')
    # go.mod always exists, fall back to root if new path doesn't exist
    return path if path else 'go.mod'


def get_components_yaml_path_for_tag(tag):
    """Get the correct components.yml path for a tag, or None if it doesn't exist."""
    return resolve_path_for_tag(tag, 'components_yml')


def get_gateway_samples_path_for_tag(tag):
    """Get the correct gateway.yml path for a tag, or None if it doesn't exist."""
    return resolve_path_for_tag(tag, 'gateway')


def get_samples_base_path_for_tag(tag):
    """Get the correct samples base path for a tag."""
    path = resolve_path_for_tag(tag, 'samples')
    # Samples always exist in one location or another
    return path if path else PATH_MIGRATIONS['samples']['old']


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
    """Read and parse the components.yml file to determine support status"""
    latest_version = get_latest_version()
    version_tag = f"v{latest_version}"
    
    # Determine correct components.yml path for this version (handles path migration)
    components_path = get_components_yaml_path_for_tag(version_tag)
    if components_path is None:
        print(f"Warning: components.yml not found at tag {version_tag}. Assuming no core components defined.")
        return []
    
    print(f"Reading core components from tag {version_tag}: {components_path}")
    content = read_file_from_git_tag(components_path, version_tag)
    if content is None:
        raise ValueError(f"Could not read components file from tag {version_tag}. Ensure the tag exists and contains the file.")
        
    try:
        data = yaml.safe_load(content)
        return data.get('core_components', [])
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing components.yml from tag {version_tag}: {e}")

def get_deprecated_components(version='main'):
    """Read and parse the components.yml file to determine deprecated status"""
    latest_version = get_latest_version()
    version_tag = f"v{latest_version}"
    
    # Determine correct components.yml path for this version (handles path migration)
    components_path = get_components_yaml_path_for_tag(version_tag)
    if components_path is None:
        print(f"Warning: components.yml not found at tag {version_tag}. Assuming no deprecated components.")
        return []
    
    print(f"Reading deprecated components from tag {version_tag}: {components_path}")
    content = read_file_from_git_tag(components_path, version_tag)
    if content is None:
        print(f"Warning: Could not read components file from tag {version_tag}. Assuming no deprecated components.")
        return []
        
    try:
        data = yaml.safe_load(content)
        deprecated = data.get('deprecated', [])
        # Handle case where 'deprecated:' exists but has no items (returns None)
        return deprecated if deprecated is not None else []
    except yaml.YAMLError as e:
        print(f"Warning: Error parsing components.yml from tag {version_tag}: {e}")
        return []

def get_component_annotations(version='main'):
    """Read and parse the components.yml file to get component annotations"""
    latest_version = get_latest_version()
    version_tag = f"v{latest_version}"
    
    # Determine correct components.yml path for this version (handles path migration)
    components_path = get_components_yaml_path_for_tag(version_tag)
    if components_path is None:
        print(f"Warning: components.yml not found at tag {version_tag}. Assuming no annotations.")
        return {}
    
    print(f"Reading component annotations from tag {version_tag}: {components_path}")
    content = read_file_from_git_tag(components_path, version_tag)
    if content is None:
        print(f"Warning: Could not read components file from tag {version_tag}. Assuming no annotations.")
        return {}
        
    try:
        data = yaml.safe_load(content)
        annotations = data.get('annotations', {})
        # Handle case where 'annotations:' exists but has no items (returns None)
        return annotations if annotations is not None else {}
    except yaml.YAMLError as e:
        print(f"Warning: Error parsing components.yml from tag {version_tag}: {e}")
        return {}

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
    elif url == 'go.opentelemetry.io/ebpf-profiler':
        html_url = 'https://github.com/open-telemetry/opentelemetry-ebpf-profiler'
        repo_link = '[OTel eBPF Profiler Repo](https://github.com/open-telemetry/opentelemetry-ebpf-profiler)'
        
    comp = {
        'name': dep[(dep.rfind('/')+1):dep.rfind(' ')].strip(),
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
    
    # Determine correct go.mod path for this version (handles path migration)
    go_mod_path = get_gomod_path_for_tag(version_tag)
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
    
    # Determine correct go.mod path for this version (handles path migration)
    go_mod_path = get_gomod_path_for_tag(version_tag)
    print(f"Reading go.mod from tag {version_tag}: {go_mod_path}")
    elastic_agent_go_mod = read_file_from_git_tag(go_mod_path, version_tag)
    if elastic_agent_go_mod is None:
        raise ValueError(f"Could not read go.mod from tag {version_tag}. Ensure the tag exists and contains the file.")

    # Get the list of core components
    core_components = get_core_components(version)
    print(f"Found {len(core_components)} core components")
    
    # Get the list of deprecated components
    deprecated_components = get_deprecated_components(version)
    print(f"Found {len(deprecated_components)} deprecated components")
    
    # Get component annotations
    component_annotations = get_component_annotations(version)
    print(f"Found {len(component_annotations)} component annotations")

    lines = elastic_agent_go_mod.splitlines()
    components_type = ['receiver', 'connector', 'processor', 'exporter', 'extension', 'provider']
    # Special components that don't follow the standard path pattern
    special_components = ['go.opentelemetry.io/ebpf-profiler']
    otel_deps = [line for line in lines if (
        not line.endswith('// indirect') and 
        ("=>" not in line) and 
        (any(f'/{comp}/' in line for comp in components_type) or 
         any(special in line for special in special_components))
    )]
    otel_components = list(map(dep_to_component, otel_deps))
    
    # Create annotation numbering
    annotation_counter = 1
    annotation_list = []
    component_annotation_map = {}
    
    # Build annotation mapping - assign numbers sequentially
    for comp in otel_components:
        comp_name = comp['name'].strip()
        if comp_name in component_annotations:
            component_annotation_map[comp_name] = annotation_counter
            annotation_list.append({
                'number': annotation_counter,
                'component_name': comp_name,
                'text': component_annotations[comp_name].get('comment', '').strip()
            })
            annotation_counter += 1
    
    # Add support status, documentation links, and annotation numbers to each component
    for comp in otel_components:
        # Extract the component name without the suffix (e.g., 'filelogreceiver' from 'filelogreceiver ')
        comp_name = comp['name'].strip()
        
        # Check if this component is deprecated (takes precedence)
        if comp_name in deprecated_components:
            comp['support_status'] = 'Deprecated'
        # Check if this component is in the core components list
        elif comp_name in core_components:
            comp['support_status'] = '[Core]'
        else:
            comp['support_status'] = '[Extended]'
            
        # Add documentation link if available
        if component_docs_mapping and comp_name in component_docs_mapping:
            comp['doc_link'] = component_docs_mapping[comp_name]['doc_path']
        else:
            comp['doc_link'] = None
        
        # Add annotation number if component has annotation
        if comp_name in component_annotation_map:
            comp['annotation_number'] = component_annotation_map[comp_name]
        else:
            comp['annotation_number'] = None

    components_grouped = defaultdict(list)

    for comp in otel_components:
        categorized = False
        for substring in components_type:
            if f'/{substring}/' in comp['dep']:
                components_grouped[f'{substring.capitalize()}s'].append(comp)
                categorized = True
                break  # Assumes each string matches only one group
        
        # Handle special components that don't follow standard path patterns
        if not categorized:
            if 'ebpf-profiler' in comp['dep']:
                # ebpf-profiler is a receiver, rename to "profiling" to match deps.go
                comp['name'] = 'profiling'
                comp['special_import'] = 'go.opentelemetry.io/ebpf-profiler/collector'
                components_grouped['Receivers'].append(comp)

    components_grouped = dict(components_grouped)

    for key, group in components_grouped.items():
        components_grouped[key] = sorted(group, key=lambda comp: comp['name'])
    
    return {
        'grouped_components': components_grouped,
        'annotations': annotation_list
    }

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

def get_all_version_tags():
    """Get all version tags from the repository"""
    try:
        result = subprocess.run(
            ['git', 'tag', '--list', 'v*'],
            capture_output=True,
            text=True,
            check=True
        )
        return [tag.strip() for tag in result.stdout.strip().split('\n') if tag.strip()]
    except subprocess.CalledProcessError as e:
        print(f"Error getting version tags: {e}")
        return []

def parse_version(tag):
    """Parse a version tag into (major, minor, patch) tuple"""
    match = re.match(r'^v(\d+)\.(\d+)\.(\d+)$', tag)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return None

def get_latest_minor_versions(major_version):
    """Get the latest patch version for each minor version of a major version"""
    all_tags = get_all_version_tags()
    versions = {}
    
    for tag in all_tags:
        parsed = parse_version(tag)
        if parsed and parsed[0] == major_version:
            major, minor, patch = parsed
            minor_key = f"{major}.{minor}"
            
            # Keep only the latest patch for each minor version
            if minor_key not in versions or parsed[2] > versions[minor_key]['patch']:
                versions[minor_key] = {
                    'minor': minor,
                    'patch': patch,
                    'tag': tag
                }
    
    # Sort by minor version (descending)
    return sorted(versions.values(), key=lambda x: x['minor'], reverse=True)

def get_minor_versions_above(major_version, min_minor):
    """Get the latest patch for each minor version >= min_minor for a major version
    
    Args:
        major_version: The major version number (e.g., 8 or 9)
        min_minor: Minimum minor version to include (e.g., 0 for 9.0+, 17 for 8.17+)
    
    Returns:
        List of version info dicts sorted by minor version (descending)
    """
    all_versions = get_latest_minor_versions(major_version)
    # Filter to only include versions >= min_minor
    filtered = [v for v in all_versions if v['minor'] >= min_minor]
    return filtered

def get_gateway_versions(major_version, min_minor):
    """Get version data for gateway configuration table
    
    Args:
        major_version: The major version number (8 or 9)
        min_minor: Minimum minor version to include
    
    Returns:
        List of dicts with 'version' and 'tag' for valid versions
    """
    print(f"Generating {major_version}.x table (versions >= {major_version}.{min_minor})")
    
    # Get all minor versions >= min_minor with their latest patches
    versions = get_minor_versions_above(major_version, min_minor)
    
    valid_versions = []
    
    for version_info in versions:
        version_str = f"{major_version}.{version_info['minor']}"
        tag_name = version_info['tag']
        
        # Determine correct gateway.yml path for this version (handles path migration)
        gateway_path = get_gateway_samples_path_for_tag(tag_name)
        if gateway_path is not None:
            valid_versions.append({
                'version': version_str,
                'tag': tag_name,
                'gateway_path': gateway_path
            })
            print(f"  {version_str} → {tag_name} ({gateway_path})")
        else:
            print(f"  Skipping {version_str}: gateway.yml not found at {tag_name}")
    
    return valid_versions

def check_markdown():
    col_version = get_collector_version()
    print(f"Collector version: {col_version}")
    
    # Load component documentation mapping
    component_docs_mapping = get_component_docs_mapping(COMPONENT_DOCS_YAML)
    print(f"Loaded {len(component_docs_mapping)} component documentation mappings")
    
    # Read components from local files
    components_result = get_otel_components(col_version, component_docs_mapping)
    
    if components_result is None:
        print("Failed to read components from local files")
        return False
        
    otel_col_version = get_otel_col_upstream_version()
    data = {
        'grouped_components': components_result['grouped_components'],
        'annotations': components_result['annotations'],
        'otel_col_version': otel_col_version,
        'version': {
            'edot_collector': col_version
        }
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
    components_result = get_otel_components(col_version, component_docs_mapping)
    
    if components_result is None:
        print("Failed to read components from local files")
        return
        
    otel_col_version = get_otel_col_upstream_version()
    data = {
        'grouped_components': components_result['grouped_components'],
        'annotations': components_result['annotations'],
        'otel_col_version': otel_col_version,
        'version': {
            'edot_collector': col_version
        }
    }
    render_components_into_file(EDOT_COLLECTOR_DIR, data, TEMPLATE_COLLECTOR_COMPONENTS_TABLE, TABLE_TAG)
    render_components_into_file(EDOT_COLLECTOR_DIR, data, TEMPLATE_COLLECTOR_OCB_FILE, DEPS_TAG)
    
    # Update sample configuration links
    print("\nUpdating sample configuration links...")
    version_tag = f"v{col_version}"
    samples_base_path = get_samples_base_path_for_tag(version_tag)
    print(f"  Version {col_version} → {samples_base_path}")
    samples_data = {
        'version': col_version,
        'samples_path': samples_base_path
    }
    render_components_into_file(
        os.path.dirname(DEFAULT_CONFIG_FILE),
        samples_data,
        TEMPLATE_SAMPLES_LINKS,
        SAMPLES_LINKS_TAG
    )
    print("Sample configuration links updated successfully!")
    
    # Update gateway configuration tables
    print("\nUpdating gateway configuration tables...")
    
    # Generate 9.x table (9.0 and above)
    gateway_9x_versions = get_gateway_versions(major_version=9, min_minor=0)
    gateway_9x_data = {'versions': gateway_9x_versions}
    
    print()
    
    # Generate 8.x table (8.17 and above)
    gateway_8x_versions = get_gateway_versions(major_version=8, min_minor=17)
    gateway_8x_data = {'versions': gateway_8x_versions}
    
    # Render tables using template
    render_components_into_file(
        os.path.dirname(DEFAULT_CONFIG_FILE), 
        gateway_9x_data, 
        TEMPLATE_GATEWAY_TABLE, 
        GATEWAY_9X_TAG
    )
    render_components_into_file(
        os.path.dirname(DEFAULT_CONFIG_FILE), 
        gateway_8x_data, 
        TEMPLATE_GATEWAY_TABLE, 
        GATEWAY_8X_TAG
    )
    
    print("\nGateway configuration tables updated successfully!")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        check_markdown()
    else:
        generate_markdown()
