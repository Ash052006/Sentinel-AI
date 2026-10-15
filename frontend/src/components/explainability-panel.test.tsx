import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ExplainabilityPanel } from './explainability-panel'
import { renderWithProviders } from '../test/utils'
import { ApiError } from '../api/client'
import { investigationsApi } from '../api/investigations'
import type { ExplainabilityResult } from '../types/api'

vi.mock('../api/investigations', () => ({
  investigationsApi: {
    explain: vi.fn(),
    explainWithAi: vi.fn(),
  },
}))

const API = vi.mocked(investigationsApi)

const CORRELATION_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'

function result(
  overrides: Partial<ExplainabilityResult> = {},
): ExplainabilityResult {
  return {
    correlation_id: CORRELATION_ID,
    generated_at: '2026-10-15T10:00:00Z',
    status: 'insufficient_evidence',
    dimensions: [
      {
        dimension: 'correlation',
        coverage: 'grounded',
        title: 'Correlation',
        summary: 'How the detections were grouped.',
        provenance: 'correlated',
        claims: [
          { text: 'Correlation status is active', evidence_ids: ['e1'] },
        ],
        reference_ids: [CORRELATION_ID],
        unavailable_reason: null,
      },
      {
        dimension: 'mitre',
        coverage: 'unavailable',
        title: 'MITRE ATT&CK',
        summary: 'No MITRE ATT&CK mapping is available.',
        provenance: 'detected',
        claims: [],
        reference_ids: [],
        unavailable_reason: 'the platform persists no ATT&CK mapping',
      },
    ],
    ai_provider: null,
    ai_model: null,
    narrative: [],
    observations: [],
    evidence: [],
    unsupported_claims: [],
    limitations: ['mitre: the platform persists no ATT&CK mapping'],
    metadata: {},
    provenance: 'ai_generated',
    ...overrides,
  }
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('ExplainabilityPanel', () => {
  it('prompts for a correlation when none is selected', () => {
    renderWithProviders(<ExplainabilityPanel correlationId={null} />)
    expect(screen.getByText('Select a correlation')).toBeInTheDocument()
    expect(API.explain).not.toHaveBeenCalled()
  })

  it('renders deterministic dimensions and grounded/unavailable coverage', async () => {
    API.explain.mockResolvedValue(result())

    renderWithProviders(<ExplainabilityPanel correlationId={CORRELATION_ID} />)

    const correlation = await screen.findByTestId('dimension-correlation')
    expect(correlation).toHaveTextContent('Correlation')
    expect(correlation).toHaveTextContent('grounded')
    expect(correlation).toHaveTextContent('Correlation status is active')
    expect(correlation).toHaveTextContent('correlated')

    const mitre = screen.getByTestId('dimension-mitre')
    expect(mitre).toHaveTextContent('unavailable')
    expect(mitre).toHaveTextContent('persists no ATT&CK mapping')

    expect(screen.getByTestId('explanation-limitations')).toHaveTextContent(
      'mitre:',
    )
    expect(API.explain).toHaveBeenCalledWith(CORRELATION_ID)
  })

  it('adds an AI narrative on demand and flags unsupported claims', async () => {
    API.explain.mockResolvedValue(result())
    API.explainWithAi.mockResolvedValue(
      result({
        status: 'explained',
        ai_provider: 'groq',
        ai_model: 'openai/gpt-oss-120b',
        narrative: [
          {
            finding_type: 'activity_pattern',
            title: 'Correlated activity',
            summary: 'Detections share one event.',
            confidence: 0.7,
            evidence_ids: ['e1'],
            metadata: {},
            provenance: 'ai_generated',
          },
        ],
        unsupported_claims: ['Unsupported escalation'],
      }),
    )

    renderWithProviders(<ExplainabilityPanel correlationId={CORRELATION_ID} />)
    await screen.findByTestId('dimension-correlation')

    await userEvent.click(
      screen.getByRole('button', { name: /add ai narrative/i }),
    )

    const narrative = await screen.findByTestId('explanation-narrative')
    expect(narrative).toHaveTextContent('Correlated activity')
    expect(screen.getByText(/groq/)).toBeInTheDocument()
    expect(screen.getByTestId('unsupported-claims')).toHaveTextContent(
      'Unsupported escalation',
    )
    expect(API.explainWithAi).toHaveBeenCalledWith(CORRELATION_ID, true)
  })

  it('surfaces the governed error detail when the explanation fails', async () => {
    API.explain.mockRejectedValue(
      new ApiError(404, 'correlation was not found'),
    )

    renderWithProviders(<ExplainabilityPanel correlationId={CORRELATION_ID} />)

    await waitFor(() =>
      expect(screen.getByText('correlation was not found')).toBeInTheDocument(),
    )
  })
})
