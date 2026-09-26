import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from './button'
import { Select } from './input'

export function Pagination({
  page,
  pageSize,
  total,
  onPage,
  onPageSize,
}: {
  page: number
  pageSize: number
  total: number
  onPage: (page: number) => void
  onPageSize: (size: number) => void
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  return (
    <div className="flex items-center justify-between gap-3 px-4 py-2.5">
      <div className="flex items-center gap-2 text-[11px] text-ink-faint">
        <span>
          {total.toLocaleString()} records · page {page} / {totalPages}
        </span>
        <Select
          aria-label="Page size"
          value={String(pageSize)}
          onChange={(event) => onPageSize(Number(event.target.value))}
          className="h-6 text-[11px]"
        >
          {[25, 50, 100, 200].map((size) => (
            <option key={size} value={size}>
              {size}/page
            </option>
          ))}
        </Select>
      </div>
      <div className="flex items-center gap-1">
        <Button
          variant="outline"
          size="sm"
          aria-label="Previous page"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
        >
          <ChevronLeft className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="outline"
          size="sm"
          aria-label="Next page"
          disabled={page >= totalPages}
          onClick={() => onPage(page + 1)}
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  )
}