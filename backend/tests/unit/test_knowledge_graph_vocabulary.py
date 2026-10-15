"""Node and edge contract tests — V3.22.

Asserts the closed vocabularies, stable identity, required provenance, and
that an unprovable relationship is simply not constructible.
"""

from __future__ import annotations

import uuid

import pytest

from app.services.knowledge_graph.vocabulary import (
    GRAPH_NAMESPACE,
    NODE_TYPES,
    RELATIONSHIPS,
    SAFE_METADATA_FIELDS,
    UNAVAILABLE_GRAPH_ENTITIES,
    NodeType,
    Provenance,
    RelationshipType,
    VocabularyError,
    build_edge,
    build_node,
    deterministic_edge_id,
    deterministic_node_id,
    parse_node_reference,
    source_reference,
    vocabulary_document,
)

#: Columns that may carry raw event payloads or provider responses and must
#: therefore never appear in the metadata allowlist.
FORBIDDEN_METADATA_COLUMNS = (
    "evidence",
    "result_metadata",
    "payload",
    "memory_metadata",
    "execution_metadata",
    "filters",
    "steps",
    "sources",
    "indicators",
    "entities",
    "techniques",
    "findings",
    "actions",
    "outcomes",
    "factors",
    "assessment_metadata",
    "context",
    "definition",
    "definition_json",
)


class TestNodeVocabulary:
    """The node vocabulary is closed and every node type is evidence-backed."""

    def test_vocabulary_is_closed_and_stable(self):
        assert {t.value for t in NodeType} == {
            "EVENT",
            "DETECTION",
            "CORRELATION",
            "RISK_ASSESSMENT",
            "THREAT_INDICATOR",
            "INCIDENT_MEMORY",
            "THREAT_HUNT",
            "APPROVAL",
            "SOAR_EXECUTION",
            "INCIDENT_REPORT",
        }

    def test_every_node_type_documents_a_source_of_truth(self):
        for spec in NODE_TYPES.values():
            assert spec.source_of_truth.strip(), f"{spec.node_type} lacks provenance"

    def test_every_node_type_has_a_provenance_value(self):
        for spec in NODE_TYPES.values():
            assert isinstance(spec.provenance, Provenance)

    def test_event_is_reference_only_and_never_claims_an_events_table(self):
        """V2 persists no events table, so the node must not imply one."""
        spec = NODE_TYPES[NodeType.EVENT]
        assert spec.reference_only is True
        assert spec.provenance is Provenance.REFERENCED_EVENT_IDENTIFIER
        assert spec.reference_prefix == "event_reference"
        # The prefix must not be a bare "event", which would read as a row id.
        assert spec.reference_prefix != "event"

    def test_no_node_type_borrows_a_persisted_provenance_label(self):
        """The reference-only event type must be distinguishable in any audit."""
        persisted = {
            spec.provenance
            for spec in NODE_TYPES.values()
            if spec.node_type is not NodeType.EVENT
        }
        assert NODE_TYPES[NodeType.EVENT].provenance not in persisted

    @pytest.mark.parametrize("node_type", list(NodeType))
    def test_metadata_allowlist_never_includes_a_json_payload_column(
        self, node_type
    ):
        allowed = set(SAFE_METADATA_FIELDS[node_type])
        assert not allowed.intersection(FORBIDDEN_METADATA_COLUMNS)

    @pytest.mark.parametrize("node_type", list(NodeType))
    def test_metadata_allowlist_covers_real_columns(self, node_type):
        assert SAFE_METADATA_FIELDS[node_type]


class TestNodeIdentity:
    """Node ids are stable, deterministic, and typed."""

    def test_node_id_is_deterministic(self):
        first = build_node(NodeType.DETECTION, "abc", "rule")
        second = build_node(NodeType.DETECTION, "abc", "different label")
        assert first["id"] == second["id"]

    def test_node_id_depends_on_type_and_source(self):
        a = deterministic_node_id(NodeType.DETECTION, "abc")
        b = deterministic_node_id(NodeType.CORRELATION, "abc")
        c = deterministic_node_id(NodeType.DETECTION, "abd")
        assert len({a, b, c}) == 3

    def test_node_id_is_a_uuid_in_the_frozen_namespace(self):
        node_id = deterministic_node_id(NodeType.CORRELATION, "x")
        assert node_id.version == 5
        assert node_id == uuid.uuid5(GRAPH_NAMESPACE, "CORRELATION:x")

    def test_node_requires_a_non_empty_source_id(self):
        with pytest.raises(VocabularyError):
            build_node(NodeType.DETECTION, "   ", "label")

    def test_source_reference_round_trips(self):
        reference = source_reference(NodeType.RISK_ASSESSMENT, "rid-1")
        assert reference == "risk_assessment:rid-1"
        assert parse_node_reference(reference) == (NodeType.RISK_ASSESSMENT, "rid-1")

    def test_unknown_reference_prefix_is_rejected(self):
        with pytest.raises(VocabularyError):
            parse_node_reference("made_up:abc")


class TestNodeMetadataSafety:
    """Metadata cannot be widened beyond the allowlist."""

    def test_disallowed_field_is_rejected(self):
        with pytest.raises(VocabularyError, match="not allowlisted"):
            build_node(NodeType.DETECTION, "d1", "l", {"evidence": {"x": 1}})

    def test_disallowed_field_is_rejected_even_if_empty(self):
        with pytest.raises(VocabularyError):
            build_node(NodeType.INCIDENT_REPORT, "r1", "l", {"payload": {}})

    def test_allowlisted_field_is_accepted(self):
        node = build_node(NodeType.DETECTION, "d1", "l", {"severity": "high"})
        assert node["metadata"]["severity"] == "high"

    def test_none_values_are_dropped_rather_than_serialized(self):
        node = build_node(NodeType.DETECTION, "d1", "l", {"severity": None})
        assert "severity" not in node["metadata"]

    def test_label_is_bounded(self):
        node = build_node(NodeType.THREAT_INDICATOR, "i1", "x" * 5000)
        assert len(node["label"]) <= NODE_TYPES[NodeType.THREAT_INDICATOR].label_max_length

    def test_blank_label_falls_back_to_the_source_id(self):
        node = build_node(NodeType.DETECTION, "d1", "   ")
        assert node["label"] == "d1"


class TestRelationshipVocabulary:
    """The relationship vocabulary is closed and typed."""

    def test_relationship_vocabulary_is_closed_and_stable(self):
        assert {r.value for r in RelationshipType} == {
            "produced_detection",
            "member_of_correlation",
            "assessed_by",
            "associated_with_indicator",
            "recalled_by",
            "requires_approval",
            "authorized_execution",
            "responded_by_execution",
            "reported_by",
            "investigated_by_hunt",
        }

    @pytest.mark.parametrize("relationship", list(RelationshipType))
    def test_every_relationship_documents_its_v2_source_of_truth(self, relationship):
        spec = RELATIONSHIPS[relationship]
        assert spec.v2_source_of_truth.strip()
        assert spec.description.strip()

    @pytest.mark.parametrize("relationship", list(RelationshipType))
    def test_every_relationship_endpoint_type_exists(self, relationship):
        spec = RELATIONSHIPS[relationship]
        assert spec.source_node_type in NODE_TYPES
        assert spec.target_node_type in NODE_TYPES

    def test_no_relationship_targets_an_excluded_entity_type(self):
        """INVESTIGATION / POLICY_DECISION / ATTACK_PATH have no rows in V2.

        Compared as plain names because a correctly-built vocabulary must not
        even define these enum members.
        """
        declared = {t.name for t in NodeType}
        for excluded in ("INVESTIGATION", "POLICY_DECISION", "ATTACK_PATH"):
            assert excluded not in declared
            assert excluded not in {t.value for t in NodeType}
        for spec in RELATIONSHIPS.values():
            assert spec.source_node_type.name not in {
                "INVESTIGATION",
                "POLICY_DECISION",
                "ATTACK_PATH",
            }
            assert spec.target_node_type.name not in {
                "INVESTIGATION",
                "POLICY_DECISION",
                "ATTACK_PATH",
            }

    def test_no_detection_to_indicator_edge_exists(self):
        """No persisted detection->indicator column exists, so no such edge."""
        pairs = {
            (spec.source_node_type, spec.target_node_type)
            for spec in RELATIONSHIPS.values()
        }
        assert (NodeType.DETECTION, NodeType.THREAT_INDICATOR) not in pairs

    def test_no_event_to_correlation_edge_exists(self):
        """Every event is reachable via its detections; a direct edge would
        duplicate an existing relationship."""
        pairs = {
            (spec.source_node_type, spec.target_node_type)
            for spec in RELATIONSHIPS.values()
        }
        assert (NodeType.EVENT, NodeType.CORRELATION) not in pairs


class TestEdgeProvenance:
    """An edge must be able to prove why it exists."""

    @staticmethod
    def _event():
        return build_node(NodeType.EVENT, "e1", "event")

    @staticmethod
    def _detection():
        return build_node(NodeType.DETECTION, "d1", "detection")

    def _valid_edge(self):
        event, detection = self._event(), self._detection()
        return build_edge(
            RelationshipType.PRODUCED_DETECTION,
            event,
            detection,
            source_reference_value="detection_result:row-1",
            evidence_references=[
                event["source_reference"],
                detection["source_reference"],
                "detection_result:row-1",
            ],
        )

    def test_valid_edge_is_constructed(self):
        edge = self._valid_edge()
        assert edge["relationship_type"] is RelationshipType.PRODUCED_DETECTION

    def test_edge_requires_a_source_reference(self):
        event, detection = self._event(), self._detection()
        with pytest.raises(VocabularyError, match="source_reference"):
            build_edge(
                RelationshipType.PRODUCED_DETECTION,
                event,
                detection,
                source_reference_value="  ",
                evidence_references=[event["source_reference"], detection["source_reference"]],
            )

    def test_edge_requires_at_least_one_evidence_reference(self):
        event, detection = self._event(), self._detection()
        with pytest.raises(VocabularyError, match="evidence"):
            build_edge(
                RelationshipType.PRODUCED_DETECTION,
                event,
                detection,
                source_reference_value="detection_result:row-1",
                evidence_references=[],
            )

    def test_evidence_must_cite_the_source_node(self):
        event, detection = self._event(), self._detection()
        with pytest.raises(VocabularyError, match="evidence must cite"):
            build_edge(
                RelationshipType.PRODUCED_DETECTION,
                event,
                detection,
                source_reference_value="detection_result:row-1",
                evidence_references=[detection["source_reference"], "detection_result:row-1"],
            )

    def test_evidence_must_cite_the_target_node(self):
        event, detection = self._event(), self._detection()
        with pytest.raises(VocabularyError, match="evidence must cite"):
            build_edge(
                RelationshipType.PRODUCED_DETECTION,
                event,
                detection,
                source_reference_value="detection_result:row-1",
                evidence_references=[event["source_reference"], "detection_result:row-1"],
            )

    def test_evidence_must_cite_the_source_reference(self):
        event, detection = self._event(), self._detection()
        with pytest.raises(VocabularyError, match="evidence must cite"):
            build_edge(
                RelationshipType.PRODUCED_DETECTION,
                event,
                detection,
                source_reference_value="detection_result:row-1",
                evidence_references=[
                    event["source_reference"],
                    detection["source_reference"],
                ],
            )

    def test_wrong_source_type_is_rejected(self):
        detection, event = self._detection(), self._event()
        with pytest.raises(VocabularyError, match="requires a EVENT source"):
            build_edge(
                RelationshipType.PRODUCED_DETECTION,
                detection,
                event,
                source_reference_value="detection_result:row-1",
                evidence_references=[
                    detection["source_reference"],
                    event["source_reference"],
                    "detection_result:row-1",
                ],
            )

    def test_unknown_relationship_is_rejected(self):
        event, detection = self._event(), self._detection()
        with pytest.raises(VocabularyError, match="unknown relationship"):
            build_edge(
                "invented_relationship",  # type: ignore[arg-type]
                event,
                detection,
                source_reference_value="x:1",
                evidence_references=[event["source_reference"]],
            )

    def test_edge_id_is_deterministic_and_order_independent(self):
        a = self._valid_edge()
        b = self._valid_edge()
        assert a["id"] == b["id"]
        assert deterministic_edge_id(
            RelationshipType.PRODUCED_DETECTION, a["source_node_id"], a["target_node_id"]
        ) == a["id"]

    def test_evidence_is_deduplicated_and_sorted_for_determinism(self):
        event, detection = self._event(), self._detection()
        edge = build_edge(
            RelationshipType.PRODUCED_DETECTION,
            event,
            detection,
            source_reference_value="detection_result:row-1",
            evidence_references=[
                "detection_result:row-1",
                detection["source_reference"],
                event["source_reference"],
                "detection_result:row-1",
            ],
        )
        assert edge["evidence_references"] == sorted(set(edge["evidence_references"]))


class TestRagBoundary:
    """RAG is contextual knowledge, never observed security evidence."""

    def test_vocabulary_declares_rag_excluded_entities(self):
        document = vocabulary_document()
        assert "INVESTIGATION" in document["unavailable_entity_types"]

    def test_no_node_type_is_a_rag_chunk(self):
        assert not any("CHUNK" in t.value or "RAG" in t.value for t in NodeType)

    def test_vocabulary_module_does_not_import_rag(self):
        """The builder must be constructible with RAG entirely absent.

        Inspects the parsed module rather than its text, so a docstring saying
        "no Gemini" cannot mask — or trigger — a false negative.
        """
        import ast
        import inspect

        from app.services.knowledge_graph import builder, vocabulary

        forbidden_modules = (
            "google",
            "genai",
            "openai",
            "anthropic",
            "httpx",
            "requests",
        )

        for module in (vocabulary, builder):
            tree = ast.parse(inspect.getsource(module))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                for name in names:
                    assert "app.services.knowledge." not in name or name.startswith(
                        "app.services.knowledge_graph"
                    ), f"{module.__name__} imports RAG module {name}"
                    for forbidden in forbidden_modules:
                        assert not name.startswith(forbidden), (
                            f"{module.__name__} imports {name}"
                        )

    def test_builder_module_imports_no_llm_client(self):
        import ast
        import inspect

        from app.services.knowledge_graph import builder

        tree = ast.parse(inspect.getsource(builder))
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        joined = " ".join(imported)
        for forbidden in (
            "google.generativeai",
            "genai",
            "openai",
            "anthropic",
            "httpx",
            "requests",
            "app.agents",
            "app.services.soc",
        ):
            assert forbidden not in joined, f"builder imports {forbidden}"


class TestUnavailableEntitiesAreDocumented:
    """Entities V2 cannot evidence are reported, not invented."""

    @pytest.mark.parametrize(
        "entity", ["INVESTIGATION", "POLICY_DECISION", "ATTACK_PATH"]
    )
    def test_exclusion_carries_an_explanation(self, entity):
        assert entity in UNAVAILABLE_GRAPH_ENTITIES
        assert UNAVAILABLE_GRAPH_ENTITIES[entity].strip()

    def test_excluded_entities_have_no_vocabulary_entry(self):
        document = vocabulary_document()
        declared = {entry["node_type"] for entry in document["node_types"]}
        for entity in UNAVAILABLE_GRAPH_ENTITIES:
            assert entity not in declared