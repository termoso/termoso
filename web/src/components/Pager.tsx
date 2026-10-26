import { useMemo, useState, type ReactNode } from "react";

export interface PageWindow {
  offset: number;
  limit: number;
}
import { TablePagination } from "@mui/material";

const OPTIONS = [10, 25, 50];
const MIN = 10;
const KEY = "termoso.rowsPerPage";

function stored(): number {
  const n = Number(localStorage.getItem(KEY));
  return OPTIONS.includes(n) ? n : MIN;
}

/** Client-side paging over an already loaded list; rows-per-page is shared across tables. */
export function usePager<T>(items: readonly T[]) {
  const [page, setPage] = useState(0);
  const [limit, setLimit] = useState(stored);
  const pages = Math.max(1, Math.ceil(items.length / limit));

  const cur = Math.min(page, pages - 1);

  const rows = useMemo(() => items.slice(cur * limit, cur * limit + limit), [items, cur, limit]);

  const pager =
    items.length > MIN ? (
      <TablePagination
        component="div"
        count={items.length}
        page={cur}
        onPageChange={(_, p) => setPage(p)}
        rowsPerPage={limit}
        onRowsPerPageChange={(e) => {
          const n = Number(e.target.value);
          localStorage.setItem(KEY, String(n));
          setLimit(n);
          setPage(0);
        }}
        rowsPerPageOptions={OPTIONS}
      />
    ) : null;

  return { rows, pager, start: cur * limit };
}

/** Same as usePager, for lists rendered from helper functions where hooks cannot be called. */
export function Paged<T>({
  items,
  children,
}: {
  items: readonly T[];
  children: (rows: T[], start: number) => ReactNode;
}) {
  const { rows, pager, start } = usePager(items);
  return (
    <>
      {children(rows, start)}
      {pager}
    </>
  );
}

/** Paging done by the server: the hook owns the window, the page returns to
 *  0 whenever `deps` (filters) change; `pager(total)` draws the controls. */
export function useServerPager(deps: unknown[] = []) {
  const key = JSON.stringify(deps);
  const [st, setSt] = useState({ page: 0, key });
  const [limit, setLimit] = useState(stored);
  const page = st.key === key ? st.page : 0;
  const setPage = (p: number) => setSt({ page: p, key });
  const pager = (total: number) => {
    const pages = Math.max(1, Math.ceil(total / limit));
    return total > MIN || page > 0 ? (
      <TablePagination
        component="div"
        count={total}
        page={Math.min(page, pages - 1)}
        onPageChange={(_, p) => setPage(p)}
        rowsPerPage={limit}
        onRowsPerPageChange={(e) => {
          const n = Number(e.target.value);
          localStorage.setItem(KEY, String(n));
          setLimit(n);
          setPage(0);
        }}
        rowsPerPageOptions={OPTIONS}
      />
    ) : null;
  };
  const win: PageWindow = { offset: page * limit, limit };
  return { ...win, window: win, pager };
}
