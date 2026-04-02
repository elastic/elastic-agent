"""
Unit tests for update-components-docs.py

Run with: python test_update_components_docs.py
Or:       python -m pytest test_update_components_docs.py -v (if pytest installed)
"""

import unittest
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
