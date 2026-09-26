import { PageHeader, Panel } from '../components/ui/card'
import { NotAvailable } from '../components/states'

export function ResponsesPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Responses"
        description="Response and mitigation execution (Step 25)."
      />
      <Panel title="Response execution" subtitle="Step 25 MockResponseProvider harness">
        <NotAvailable
          simulation
          body="Response execution is deliberately a simulation harness: every Step 25 response action is run against the MockResponseProvider, produces an in-memory EXECUTED / FAILED / SKIPPED / REJECTED outcome, and never touches real infrastructure. Step 25 defines no persistence and no query API, so no response results are stored or served. This page shows the simulation-only state; nothing is fabricated."
        />
      </Panel>
      <Panel title="What Step 25 actually does" subtitle="Summary of the implemented layer">
        <ul className="list-disc space-y-1.5 pl-5 text-[11px] leading-relaxed text-ink-dim">
          <li>
            A permitted policy decision gates each response attempt (Step 24).
          </li>
          <li>
            A validated provider executes the action; the default provider is
            strictly simulated and behaves as an abstraction, never a real
            effector.
          </li>
          <li>
            Outcomes are response results with RESPONSE_EXECUTED provenance —
            created, executed, and discarded in memory.
          </li>
        </ul>
      </Panel>
    </div>
  )
}