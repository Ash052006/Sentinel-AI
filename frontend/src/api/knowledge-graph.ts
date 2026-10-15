import { api } from './client'
import type {
  KnowledgeNode,
  KnowledgeTraversal,
  KnowledgeVocabulary,
} from '../types/api'

/**
 * V3.22 knowledge-graph engine — read-only graph projection over persisted V2
 * rows. Never mutates; graph state is written solely by the deterministic
 * builder (`app.cli build-knowledge-graph`).
 *
 * `/correlations/{id}` is the canonical spelling. The short form
 * `/knowledge-graph/{id}` is equivalent and is used here because it is the
 * shortest documented path; the backend rejects a non-UUID segment with 422.
 */
export const knowledgeGraphApi = {
  correlationGraph: (correlationId: string): Promise<KnowledgeTraversal> =>
    api.get<KnowledgeTraversal>(
      `/api/knowledge-graph/correlations/${encodeURIComponent(correlationId)}`,
    ),

  node: (nodeId: string): Promise<KnowledgeNode> =>
    api.get<KnowledgeNode>(
      `/api/knowledge-graph/nodes/${encodeURIComponent(nodeId)}`,
    ),

  neighbors: (
    nodeId: string,
    maxDepth = 1,
  ): Promise<KnowledgeTraversal> =>
    api.get<KnowledgeTraversal>(
      `/api/knowledge-graph/nodes/${encodeURIComponent(nodeId)}/neighbors`,
      { max_depth: maxDepth },
    ),

  vocabulary: (): Promise<KnowledgeVocabulary> =>
    api.get<KnowledgeVocabulary>('/api/knowledge-graph/vocabulary'),
}