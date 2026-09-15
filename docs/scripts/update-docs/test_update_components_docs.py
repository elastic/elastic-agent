"""
Unit tests for update-components-docs.py

Run with: python test_update_components_docs.py
Or:       python -m pytest test_update_components_docs.py -v (if pytest installed)
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from importlib.machinery import SourceFileLoader

# Load the script module
script = SourceFileLoader('update_components_docs', 'update-components-docs.py').load_module()


class TestParseVersionTag(unittest.TestCase):
    """Tests for parse_version_tag function."""

    def test_standard_version_with_v_prefix(self):
        self.assertEqual(script.parse_version_tag('v9.2.2'), (9, 2, 2))

    def test_version_without_v_prefix(self):
        self.assertEqual(script.parse_version_tag('9.2.2'), (9, 2, 2))

    def test_version_with_suffix(self):
        self.assertEqual(script.parse_version_tag('v9.3.0-test'), (9, 3, 0))
        self.assertEqual(script.parse_version_tag('v9.3.0-rc1'), (9, 3, 0))
        self.assertEqual(script.parse_version_tag('v9.3.0+build123'), (9, 3, 0))

    def test_double_digit_versions(self):
        self.assertEqual(script.parse_version_tag('v10.15.23'), (10, 15, 23))

    def test_zero_versions(self):
        self.assertEqual(script.parse_version_tag('v9.0.0'), (9, 0, 0))

    def test_invalid_version_returns_none(self):
        self.assertIsNone(script.parse_version_tag('main'))
        self.assertIsNone(script.parse_version_tag('feature-branch'))
        self.assertIsNone(script.parse_version_tag(''))

    def test_partial_version_returns_none(self):
        self.assertIsNone(script.parse_version_tag('v9.2'))
        self.assertIsNone(script.parse_version_tag('v9'))


class TestResolvePathForTag(unittest.TestCase):
    """Tests for resolve_path_for_tag function."""

    # Components YAML tests
    def test_components_yml_new_path_for_9_3_plus(self):
        self.assertEqual(script.resolve_path_for_tag('v9.3.0', 'components_yml'), 'internal/edot/components.yml')
        self.assertEqual(script.resolve_path_for_tag('v9.4.0', 'components_yml'), 'internal/edot/components.yml')
        self.assertEqual(script.resolve_path_for_tag('v10.0.0', 'components_yml'), 'internal/edot/components.yml')

    def test_components_yml_old_path_for_9_2_x(self):
        self.assertEqual(script.resolve_path_for_tag('v9.2.2', 'components_yml'), 'internal/pkg/otel/components.yml')
        self.assertEqual(script.resolve_path_for_tag('v9.2.1', 'components_yml'), 'internal/pkg/otel/components.yml')

    def test_components_yml_none_for_pre_9_2_1(self):
        # components.yml didn't exist before v9.2.1
        self.assertIsNone(script.resolve_path_for_tag('v9.2.0', 'components_yml'))
        self.assertIsNone(script.resolve_path_for_tag('v9.1.8', 'components_yml'))
        self.assertIsNone(script.resolve_path_for_tag('v9.0.8', 'components_yml'))

    # Samples tests
    def test_samples_new_path_for_9_3_plus(self):
        self.assertEqual(script.resolve_path_for_tag('v9.3.0', 'samples'), 'internal/edot/samples')

    def test_samples_old_path_for_pre_9_3(self):
        self.assertEqual(script.resolve_path_for_tag('v9.2.2', 'samples'), 'internal/pkg/otel/samples')
        self.assertEqual(script.resolve_path_for_tag('v9.0.0', 'samples'), 'internal/pkg/otel/samples')

    # Gateway tests
    def test_gateway_new_path_for_9_3_plus(self):
        expected = 'internal/edot/samples/linux/gateway.yml'
        self.assertEqual(script.resolve_path_for_tag('v9.3.0', 'gateway'), expected)

    def test_gateway_old_path_for_pre_9_3(self):
        expected = 'internal/pkg/otel/samples/linux/gateway.yml'
        self.assertEqual(script.resolve_path_for_tag('v9.2.2', 'gateway'), expected)
        self.assertEqual(script.resolve_path_for_tag('v8.19.0', 'gateway'), expected)

    # go.mod tests
    def test_gomod_new_path_for_9_plus(self):
        self.assertEqual(script.resolve_path_for_tag('v9.0.0', 'gomod'), 'internal/edot/go.mod')

    def test_gomod_old_path_for_pre_9(self):
        self.assertEqual(script.resolve_path_for_tag('v8.19.0', 'gomod'), 'go.mod')

    # Error handling
    def test_invalid_path_type_raises_error(self):
        with self.assertRaises(ValueError) as ctx:
            script.resolve_path_for_tag('v9.2.2', 'invalid_type')
        self.assertIn('Unknown path type', str(ctx.exception))


class TestResolvePathForTagWithFallback(unittest.TestCase):
    """Tests for resolve_path_for_tag with file existence fallback."""

    def test_fallback_to_file_check_when_version_parse_fails(self):
        """When version can't be parsed (e.g., 'main'), fall back to file check."""
        with patch.object(script, 'check_file_exists_at_tag') as mock_check:
            mock_check.side_effect = [True, False]  # new path exists
            result = script.resolve_path_for_tag('main', 'components_yml', fallback_to_file_check=True)
            self.assertEqual(result, 'internal/edot/components.yml')
            mock_check.assert_called()

    def test_no_fallback_returns_none_for_unparseable_version(self):
        """When fallback is disabled and version can't be parsed, return None."""
        result = script.resolve_path_for_tag('main', 'components_yml', fallback_to_file_check=False)
        self.assertIsNone(result)


class TestConvenienceFunctions(unittest.TestCase):
    """Tests for convenience wrapper functions."""

    def test_get_gomod_path_for_tag(self):
        self.assertEqual(script.get_gomod_path_for_tag('v9.2.2'), 'internal/edot/go.mod')
        self.assertEqual(script.get_gomod_path_for_tag('v8.19.0'), 'go.mod')

    def test_get_components_yaml_path_for_tag(self):
        self.assertEqual(script.get_components_yaml_path_for_tag('v9.3.0'), 'internal/edot/components.yml')
        self.assertEqual(script.get_components_yaml_path_for_tag('v9.2.2'), 'internal/pkg/otel/components.yml')
        self.assertIsNone(script.get_components_yaml_path_for_tag('v9.1.0'))

    def test_get_gateway_samples_path_for_tag(self):
        self.assertEqual(script.get_gateway_samples_path_for_tag('v9.3.0'), 'internal/edot/samples/linux/gateway.yml')
        self.assertEqual(script.get_gateway_samples_path_for_tag('v9.2.2'), 'internal/pkg/otel/samples/linux/gateway.yml')

    def test_get_samples_base_path_for_tag(self):
        self.assertEqual(script.get_samples_base_path_for_tag('v9.3.0'), 'internal/edot/samples')
        self.assertEqual(script.get_samples_base_path_for_tag('v9.2.2'), 'internal/pkg/otel/samples')


class TestPathMigrationsConfig(unittest.TestCase):
    """Tests to verify PATH_MIGRATIONS configuration is correct."""

    def test_all_path_types_have_required_keys(self):
        required_keys = {'new', 'old', 'since'}
        for path_type, config in script.PATH_MIGRATIONS.items():
            missing = required_keys - set(config.keys())
            self.assertFalse(missing, f"{path_type} missing keys: {missing}")

    def test_since_versions_are_valid_tuples(self):
        for path_type, config in script.PATH_MIGRATIONS.items():
            since = config['since']
            self.assertIsInstance(since, tuple, f"{path_type}.since should be tuple")
            self.assertEqual(len(since), 3, f"{path_type}.since should have 3 elements")
            self.assertTrue(all(isinstance(v, int) for v in since), f"{path_type}.since should be integers")

    def test_components_yml_has_exists_since(self):
        """components.yml has special exists_since since it was added later."""
        self.assertIn('exists_since', script.PATH_MIGRATIONS['components_yml'])
        self.assertEqual(script.PATH_MIGRATIONS['components_yml']['exists_since'], (9, 2, 1))


class TestVersionComparison(unittest.TestCase):
    """Tests for version tuple comparison behavior."""

    def test_version_comparison_works_as_expected(self):
        """Verify Python tuple comparison works for our version scheme."""
        self.assertGreater((9, 3, 0), (9, 2, 2))
        self.assertGreaterEqual((9, 3, 0), (9, 3, 0))
        self.assertGreater((9, 2, 1), (9, 2, 0))
        self.assertGreater((10, 0, 0), (9, 99, 99))
        self.assertLess((9, 2, 0), (9, 2, 1))


class TestDocCoverageIssues(unittest.TestCase):
    """Tests for get_doc_coverage_issues (documentation coverage detection)."""

    @staticmethod
    def _resolver(components_dir):
        # Map any site doc path to a file of the same name in the temp dir.
        return lambda doc_path: components_dir / Path(doc_path).name

    def test_missing_target_and_orphaned_pages(self):
        with tempfile.TemporaryDirectory() as d:
            components_dir = Path(d) / 'components'
            components_dir.mkdir()
            # A mapped page that exists on disk.
            (components_dir / 'filelogreceiver.md').write_text('x', encoding='utf-8')
            # A page that exists but is not referenced by any mapping.
            (components_dir / 'attributesprocessor.md').write_text('x', encoding='utf-8')
            # A non-component page that must be ignored.
            (components_dir / 'migrate-components.md').write_text('x', encoding='utf-8')

            mapping = {
                'filelogreceiver': {
                    'doc_path': '/reference/edot-collector/components/filelogreceiver.md'
                },
                # Mapping whose target file does not exist -> broken link.
                'ghostreceiver': {
                    'doc_path': '/reference/edot-collector/components/ghostreceiver.md'
                },
            }

            issues = script.get_doc_coverage_issues(
                mapping,
                components_dir=components_dir,
                resolver=self._resolver(components_dir),
            )

            missing = {m['component'] for m in issues['missing_targets']}
            self.assertEqual(missing, {'ghostreceiver'})
            self.assertEqual(
                issues['missing_targets'][0]['doc_path'],
                '/reference/edot-collector/components/ghostreceiver.md',
            )

            self.assertIn('attributesprocessor.md', issues['orphaned_pages'])
            self.assertNotIn('filelogreceiver.md', issues['orphaned_pages'])
            self.assertNotIn('migrate-components.md', issues['orphaned_pages'])

    def test_no_issues_when_all_mapped_and_present(self):
        with tempfile.TemporaryDirectory() as d:
            components_dir = Path(d) / 'components'
            components_dir.mkdir()
            (components_dir / 'filelogreceiver.md').write_text('x', encoding='utf-8')

            mapping = {
                'filelogreceiver': {
                    'doc_path': '/reference/edot-collector/components/filelogreceiver.md'
                },
            }

            issues = script.get_doc_coverage_issues(
                mapping,
                components_dir=components_dir,
                resolver=self._resolver(components_dir),
            )
            self.assertEqual(issues['missing_targets'], [])
            self.assertEqual(issues['orphaned_pages'], [])

    def test_empty_mapping_returns_no_issues(self):
        with tempfile.TemporaryDirectory() as d:
            components_dir = Path(d) / 'components'
            components_dir.mkdir()
            issues = script.get_doc_coverage_issues(
                {}, components_dir=components_dir, resolver=self._resolver(components_dir)
            )
            self.assertEqual(issues['missing_targets'], [])
            self.assertEqual(issues['orphaned_pages'], [])


class TestSinceToMinor(unittest.TestCase):
    """Tests for since_to_minor (Added-in badge version formatting)."""

    def test_converts_to_major_minor(self):
        self.assertEqual(script.since_to_minor('v9.5.0'), '9.5')
        self.assertEqual(script.since_to_minor('9.5.3'), '9.5')
        self.assertEqual(script.since_to_minor('v10.0.0'), '10.0')

    def test_empty_or_unparseable_returns_empty(self):
        self.assertEqual(script.since_to_minor(''), '')
        self.assertEqual(script.since_to_minor(None), '')
        self.assertEqual(script.since_to_minor('main'), '')


class TestIsNewComponent(unittest.TestCase):
    """Tests for is_new_component (New-marker gating)."""

    def test_matches_latest_minor(self):
        self.assertTrue(script.is_new_component('v9.5.0', '9.5.3'))
        self.assertTrue(script.is_new_component('v9.5.3', 'v9.5.3'))

    def test_older_minor_is_not_new(self):
        self.assertFalse(script.is_new_component('v9.4.0', '9.5.3'))
        self.assertFalse(script.is_new_component('v9.0.0', '9.5.0'))

    def test_empty_or_main_is_not_new(self):
        self.assertFalse(script.is_new_component('', '9.5.3'))
        self.assertFalse(script.is_new_component('v9.5.0', 'main'))


build_pr_body = SourceFileLoader('build_pr_body', 'build_pr_body.py').load_module()


class TestBuildPrBody(unittest.TestCase):
    """Tests for build_pr_body.build_body (automated PR description rendering)."""

    def test_base_body_has_corrected_source_links(self):
        body = build_pr_body.build_body({}, 'v9.5.3')
        # Links must point at the real generation sources (regression guard for
        # the previous components.yaml / root go.mod links).
        self.assertIn('/blob/v9.5.3/internal/edot/go.mod', body)
        self.assertIn('/blob/v9.5.3/internal/edot/components.yml', body)
        self.assertNotIn('components.yaml', body)
        self.assertNotIn('/blob/v9.5.3/go.mod', body)

    def test_no_review_sections_when_empty(self):
        body = build_pr_body.build_body({}, 'v9.5.3')
        self.assertNotIn('New components detected', body)
        self.assertNotIn('Documentation coverage gaps', body)

    def test_new_components_section_rendered(self):
        body = build_pr_body.build_body({'newly_stamped': ['fooreceiver', 'barexporter']}, 'v9.5.3')
        self.assertIn('## ⚠️ New components detected', body)
        self.assertIn('- `fooreceiver`', body)
        self.assertIn('- `barexporter`', body)

    def test_doc_coverage_section_rendered(self):
        data = {
            'doc_coverage': {
                'missing_targets': [
                    {'component': 'ghostreceiver',
                     'doc_path': '/reference/edot-collector/components/ghostreceiver.md'}
                ],
                'orphaned_pages': ['attributesprocessor.md'],
            }
        }
        body = build_pr_body.build_body(data, 'v9.5.3')
        self.assertIn('## 📄 Documentation coverage gaps', body)
        self.assertIn('`ghostreceiver`', body)
        self.assertIn('`attributesprocessor.md`', body)


if __name__ == '__main__':
    unittest.main(verbosity=2)
