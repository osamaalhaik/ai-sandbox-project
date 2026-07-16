(() => {
    const escapeHtml = value => String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

    const timeText = value => {
        if (!value) {
            return "—";
        }

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {
            return "—";
        }

        return date.toLocaleString();
    };

    const riskClass = value => {
        const risk = String(value || "").toLowerCase();

        if (
            risk === "critical"
            || risk === "high"
        ) {
            return "risk-high";
        }

        if (
            risk === "suspicious"
            || risk === "medium"
        ) {
            return "risk-medium";
        }

        return "risk-low";
    };

    const statusClass = value => {
        const status = String(value || "").toLowerCase();

        if (
            status.includes("block")
            || status.includes("reject")
        ) {
            return "status-block";
        }

        if (
            status.includes("review")
            || status.includes("confirm")
        ) {
            return "status-review";
        }

        return "status-allow";
    };

    const debounce = (
        callback,
        delay = 300,
    ) => {
        let timeout;

        return (...args) => {
            window.clearTimeout(timeout);

            timeout = window.setTimeout(
                () => callback(...args),
                delay,
            );
        };
    };

    const initialize = container => {
        const type = container.dataset.serverTable;

        if (
            type !== "runs"
            && type !== "alerts"
        ) {
            return;
        }

        const body = container.querySelector("tbody");
        const search = container.querySelector(
            "[data-table-search]",
        );

        const filters = [
            ...container.querySelectorAll(
                "[data-table-filter]",
            ),
        ];

        const headers = [
            ...container.querySelectorAll(
                "thead th[data-sort]",
            ),
        ];

        const empty = container.querySelector(
            "[data-table-empty]",
        );

        const tools = container.querySelector(
            ".table-tools",
        );

        if (!body) {
            return;
        }

        const state = {
            page: 1,
            pageSize: 10,
            pages: 1,
            total: 0,
            sortBy: "created_at",
            sortDir: "desc",
            loading: false,
        };

        const footer = document.createElement("div");

        footer.className = "table-footer server-table-footer";

        footer.innerHTML = `
            <div class="table-result-count">
                <strong data-server-visible>0</strong>
                <span>of</span>
                <strong data-server-total>0</strong>
                <span>records</span>
            </div>

            <div class="table-footer-controls">
                <label class="page-size-control">
                    <span>Rows</span>
                    <select data-server-page-size>
                        <option value="10">10</option>
                        <option value="25">25</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                </label>

                <div
                    class="table-pagination"
                    data-server-pagination
                ></div>
            </div>
        `;

        container.appendChild(footer);

        const pageSize = footer.querySelector(
            "[data-server-page-size]",
        );

        const pagination = footer.querySelector(
            "[data-server-pagination]",
        );

        const visibleCount = footer.querySelector(
            "[data-server-visible]",
        );

        const totalCount = footer.querySelector(
            "[data-server-total]",
        );

        const exportButton = document.createElement(
            "button",
        );

        exportButton.type = "button";
        exportButton.className = (
            "filter-button export-button"
        );
        exportButton.textContent = "⇩ Export CSV";

        tools?.appendChild(exportButton);

        const queryParameters = (
            includePagination = true,
        ) => {
            const params = new URLSearchParams();
            const query = search?.value.trim();

            if (query) {
                params.set("q", query);
            }

            filters.forEach(filter => {
                if (filter.value) {
                    params.set(
                        filter.dataset.tableFilter,
                        filter.value,
                    );
                }
            });

            params.set(
                "sort_by",
                state.sortBy,
            );

            params.set(
                "sort_dir",
                state.sortDir,
            );

            if (includePagination) {
                params.set(
                    "page",
                    String(state.page),
                );

                params.set(
                    "page_size",
                    String(state.pageSize),
                );
            }

            return params;
        };

        const endpoint = () => (
            `/api/operations/${type}`
        );

        const exportEndpoint = () => (
            `/api/operations/${type}.csv`
        );

        const renderRuns = items => {
            return items.map(item => {
                const runId = escapeHtml(item.run_id);
                const command = escapeHtml(item.command);
                const executable = escapeHtml(
                    item.executable || "—",
                );

                const status = escapeHtml(
                    item.status || "unknown",
                );

                const risk = escapeHtml(
                    item.risk_level || "low",
                );

                const decision = escapeHtml(
                    item.decision || "unknown",
                );

                return `
                    <tr>
                        <td>
                            <code title="${command}">
                                ${command}
                            </code>
                            <small>
                                ${runId.slice(0, 16)}…
                            </small>
                        </td>
                        <td>${executable}</td>
                        <td>
                            <span class="state-label state-${status}">
                                ${status}
                            </span>
                        </td>
                        <td>
                            <span class="risk-badge ${riskClass(risk)}">
                                ${Number(item.risk_score || 0)} · ${risk}
                            </span>
                        </td>
                        <td>
                            <span class="status-badge ${statusClass(decision)}">
                                ${decision}
                            </span>
                        </td>
                        <td>${timeText(item.created_at)}</td>
                        <td>
                            <a
                                class="row-action"
                                href="/runs/${runId}"
                            >
                                Open
                            </a>
                        </td>
                    </tr>
                `;
            }).join("");
        };

        const renderAlerts = items => {
            return items.map(item => {
                const runId = escapeHtml(item.run_id);
                const level = escapeHtml(
                    item.level || "low",
                );

                const title = escapeHtml(
                    item.title || "Security alert",
                );

                const message = escapeHtml(
                    item.message || "",
                );

                return `
                    <tr>
                        <td>
                            <span class="risk-badge ${riskClass(level)}">
                                ${level}
                            </span>
                        </td>
                        <td>
                            <strong>${title}</strong>
                        </td>
                        <td class="message-cell">
                            ${message}
                        </td>
                        <td>
                            <code>${runId.slice(0, 16)}…</code>
                        </td>
                        <td>${timeText(item.created_at)}</td>
                        <td>
                            <a
                                class="row-action"
                                href="/runs/${runId}"
                            >
                                Inspect
                            </a>
                        </td>
                    </tr>
                `;
            }).join("");
        };

        const renderPagination = () => {
            pagination.innerHTML = "";

            const create = (
                label,
                page,
                disabled = false,
                active = false,
            ) => {
                const button = document.createElement(
                    "button",
                );

                button.type = "button";
                button.textContent = label;
                button.dataset.page = String(page);
                button.disabled = disabled;

                if (active) {
                    button.classList.add("active");
                }

                return button;
            };

            pagination.appendChild(
                create(
                    "‹",
                    state.page - 1,
                    state.page <= 1,
                ),
            );

            const start = Math.max(
                1,
                state.page - 2,
            );

            const end = Math.min(
                state.pages,
                start + 4,
            );

            for (
                let page = start;
                page <= end;
                page += 1
            ) {
                pagination.appendChild(
                    create(
                        String(page),
                        page,
                        false,
                        page === state.page,
                    ),
                );
            }

            pagination.appendChild(
                create(
                    "›",
                    state.page + 1,
                    state.page >= state.pages,
                ),
            );
        };

        const setLoading = loading => {
            state.loading = loading;
            container.classList.toggle(
                "server-table-loading",
                loading,
            );

            if (loading) {
                body.innerHTML = `
                    <tr>
                        <td
                            colspan="9"
                            class="server-loading-cell"
                        >
                            Loading operational data…
                        </td>
                    </tr>
                `;
            }
        };

        const load = async () => {
            if (state.loading) {
                return;
            }

            setLoading(true);

            try {
                const response = await fetch(
                    `${endpoint()}?${queryParameters()}`,
                    {
                        headers: {
                            Accept: "application/json",
                        },
                        cache: "no-store",
                    },
                );

                if (!response.ok) {
                    throw new Error(
                        `HTTP ${response.status}`,
                    );
                }

                const payload = await response.json();
                const items = Array.isArray(
                    payload.items,
                )
                    ? payload.items
                    : [];

                state.page = Number(
                    payload.page || 1,
                );

                state.pages = Number(
                    payload.pages || 1,
                );

                state.total = Number(
                    payload.total || 0,
                );

                body.innerHTML = (
                    type === "runs"
                        ? renderRuns(items)
                        : renderAlerts(items)
                );

                visibleCount.textContent = String(
                    items.length,
                );

                totalCount.textContent = String(
                    state.total,
                );

                empty.hidden = state.total > 0;

                renderPagination();
            } catch (error) {
                body.innerHTML = `
                    <tr>
                        <td
                            colspan="9"
                            class="server-error-cell"
                        >
                            Unable to load data: ${escapeHtml(error.message)}
                        </td>
                    </tr>
                `;

                visibleCount.textContent = "0";
                totalCount.textContent = "0";
                empty.hidden = true;
            } finally {
                setLoading(false);
            }
        };

        const delayedLoad = debounce(() => {
            state.page = 1;
            load();
        });

        search?.addEventListener(
            "input",
            delayedLoad,
        );

        filters.forEach(filter => {
            filter.addEventListener(
                "change",
                () => {
                    state.page = 1;
                    load();
                },
            );
        });

        pageSize?.addEventListener(
            "change",
            () => {
                state.pageSize = Number(
                    pageSize.value,
                ) || 10;

                state.page = 1;
                load();
            },
        );

        pagination.addEventListener(
            "click",
            event => {
                const button = event.target.closest(
                    "button[data-page]",
                );

                if (
                    !button
                    || button.disabled
                ) {
                    return;
                }

                state.page = Number(
                    button.dataset.page,
                ) || 1;

                load();
            },
        );

        headers.forEach(header => {
            header.classList.add(
                "sortable-column",
            );

            const indicator = document.createElement(
                "span",
            );

            indicator.className = "sort-indicator";
            indicator.textContent = "↕";

            header.appendChild(indicator);

            header.addEventListener(
                "click",
                () => {
                    const sortBy = (
                        header.dataset.sort
                    );

                    if (state.sortBy === sortBy) {
                        state.sortDir = (
                            state.sortDir === "asc"
                                ? "desc"
                                : "asc"
                        );
                    } else {
                        state.sortBy = sortBy;
                        state.sortDir = "asc";
                    }

                    headers.forEach(item => {
                        item.classList.remove(
                            "sorted-ascending",
                            "sorted-descending",
                        );

                        const icon = item.querySelector(
                            ".sort-indicator",
                        );

                        if (icon) {
                            icon.textContent = "↕";
                        }
                    });

                    header.classList.add(
                        state.sortDir === "asc"
                            ? "sorted-ascending"
                            : "sorted-descending",
                    );

                    indicator.textContent = (
                        state.sortDir === "asc"
                            ? "↑"
                            : "↓"
                    );

                    state.page = 1;
                    load();
                },
            );
        });

        exportButton.addEventListener(
            "click",
            () => {
                window.location.href = (
                    `${exportEndpoint()}?`
                    + queryParameters(false)
                );
            },
        );

        const requestedSearch = (
            new URLSearchParams(
                window.location.search,
            ).get("search")
        );

        if (
            requestedSearch
            && search
        ) {
            search.value = requestedSearch;
        }

        load();
    };

    document
        .querySelectorAll(
            "[data-server-table]",
        )
        .forEach(initialize);
})();
