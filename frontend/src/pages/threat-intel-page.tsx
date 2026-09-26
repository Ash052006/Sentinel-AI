import { PageHeader, Panel } from '../components/ui/card'
import { NotAvailable } from '../components/states'

export function ThreatIntelPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <PageHeader
        title="Threat intelligence"
        description="What SentinelAI knows about external threat indicators."
      />
      <Panel title="Indicator lookups" subtitle="Step 8 provider layer">
        <NotAvailable
          body="The Step 8 threat-intelligence analysis contract and the provider layer (registry of external enrichment sources) exist, but V1 persists and serves no threat-intelligence indicators through any API endpoint. With no read surface, no indicator data exists to display, so this view reports not available rather than fabricating findings."
        />
      </Panel>
    </div>
  )
}