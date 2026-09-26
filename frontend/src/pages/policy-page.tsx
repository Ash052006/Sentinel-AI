import { PageHeader, Panel } from '../components/ui/card'
import { NotAvailable } from '../components/states'

export function PolicyPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Policy"
        description="Declarative response-approval policy (Step 24)."
      />
      <Panel title="Policy decisions" subtitle="Step 24 Policy Decision Engine">
        <NotAvailable
          body="The deterministic Policy Decision Engine evaluates declarative rules over Risk / Investigation / Attribution context and emits auditable ALLOWED / DENIED / REQUIRES_APPROVAL outcomes, but Step 24 defines no persistence layer and no policy API. Decisions are produced in-memory during execution only. Because no decision is stored or served, this view is marked Not available — it never shows fabricated policy evaluations."
        />
      </Panel>
    </div>
  )
}