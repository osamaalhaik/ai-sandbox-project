(() => {
    const normalize = value => String(value ?? "").trim().toLowerCase();

    const csvValue = value => {
        const text = String(value ?? "").replace(/\s+/g, " ").trim();
        return `"${text.replaceAll('"', '""')}"`;
    };

    const comparableValue = value => {
        const text = String(value ?? "").replace(/\s+/g, " ").trim();
        const numeric = Number(text.replace(/[^\d.-]/g, ""));

        if (
            text
            && Number.isFinite(numeric)
            && /[\d]/.test(text)
        ) {
            return {
                type: "number",
                value: numeric,
            };
        }

        const timestamp = Date.parse(text);

        if (
            text
            && Number.isFinite(timestamp)
            && /[-/:]/.test(text)
        ) {
            return {
                type: "date",
                value: timestamp,
            };
        }

        return {
            type: "text",
            value: normalize(text),
        };
    };

    const showToast = message => {
        let stack = document.querySelector(".toast-stack");

        if (!stack) {
            stack = document.createElement("div");
            stack.className = "toast-stack";
            document.body.appendChild(stack);
        }

        const toast = document.createElement("div");
        toast.className = "toast-message";
        toast.textContent = message;

        stack.appendChild(toast);

        window.setTimeout(() => {
            toast.classList.add("visible");
        }, 10);

        window.setTimeout(() => {
            toast.classList.remove("visible");

            window.setTimeout(() => {
                toast.remove();
            }, 220);
        }, 2600);
    };

    const downloadCsv = (filename, headers, rows) => {
        const lines = [
            headers.map(csvValue).join(","),
            ...rows.map(row => row.map(csvValue).join(",")),
        ];

        const blob = new Blob(
            [lines.join("\n")],
            {
                type: "text/csv;charset=utf-8",
            },
        );

        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");

        link.href = url;
        link.download = filename;

        document.body.appendChild(link);
        link.click();
        link.remove();

        URL.revokeObjectURL(url);
    };

    const initializeTable = container => {
        if (container.dataset.serverTable) {
            return;
        }

        if (container.dataset.tableEnhanced === "true") {
            return;
        }

        const table = container.querySelector("table.data-table");
        const body = table?.querySelector("tbody");

        if (!table || !body) {
            return;
        }

        container.dataset.tableEnhanced = "true";

        const rows = [
            ...body.querySelectorAll("[data-table-row]"),
        ];

        const headers = [
            ...table.querySelectorAll("thead th"),
        ];

        const searchInput = container.querySelector(
            "[data-table-search]",
        );

        const filters = [
            ...container.querySelectorAll("[data-table-filter]"),
        ];

        const emptyState = container.querySelector(
            "[data-table-empty]",
        );

        const toolbar = container.querySelector(".table-tools");

        let currentPage = 1;
        let pageSize = 10;
        let sortIndex = -1;
        let sortDirection = 1;

        const footer = document.createElement("div");
        footer.className = "table-footer";
        footer.innerHTML = `
            <div class="table-result-count">
                <strong data-result-visible>0</strong>
                <span>of</span>
                <strong data-result-total>${rows.length}</strong>
                <span>records</span>
            </div>

            <div class="table-footer-controls">
                <label class="page-size-control">
                    <span>Rows</span>
                    <select data-page-size>
                        <option value="10">10</option>
                        <option value="25">25</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                </label>

                <div class="table-pagination" data-pagination></div>
            </div>
        `;

        container.appendChild(footer);

        let exportButton = null;

        if (toolbar) {
            exportButton = document.createElement("button");
            exportButton.type = "button";
            exportButton.className = "filter-button export-button";
            exportButton.innerHTML = "⇩ Export CSV";
            toolbar.appendChild(exportButton);
        }

        const visibleCount = footer.querySelector(
            "[data-result-visible]",
        );

        const totalCount = footer.querySelector(
            "[data-result-total]",
        );

        const pageSizeSelect = footer.querySelector(
            "[data-page-size]",
        );

        const pagination = footer.querySelector(
            "[data-pagination]",
        );

        const matchesFilters = row => {
            const query = normalize(searchInput?.value);
            const searchable = normalize(
                row.dataset.search || row.textContent,
            );

            if (query && !searchable.includes(query)) {
                return false;
            }

            return filters.every(filter => {
                const selected = normalize(filter.value);

                if (!selected) {
                    return true;
                }

                const key = filter.dataset.tableFilter;
                return normalize(row.dataset[key]) === selected;
            });
        };

        const sortedRows = () => {
            const ordered = [...rows];

            if (sortIndex < 0) {
                return ordered;
            }

            ordered.sort((left, right) => {
                const leftCell = left.children[sortIndex];
                const rightCell = right.children[sortIndex];

                const leftValue = comparableValue(
                    leftCell?.textContent,
                );

                const rightValue = comparableValue(
                    rightCell?.textContent,
                );

                if (
                    leftValue.type === rightValue.type
                    && leftValue.value < rightValue.value
                ) {
                    return -1 * sortDirection;
                }

                if (
                    leftValue.type === rightValue.type
                    && leftValue.value > rightValue.value
                ) {
                    return 1 * sortDirection;
                }

                return String(leftValue.value)
                    .localeCompare(
                        String(rightValue.value),
                        undefined,
                        {
                            numeric: true,
                            sensitivity: "base",
                        },
                    ) * sortDirection;
            });

            return ordered;
        };

        const filteredRows = () => {
            return sortedRows().filter(matchesFilters);
        };

        const renderPagination = pageCount => {
            pagination.innerHTML = "";

            const createButton = (
                label,
                page,
                disabled = false,
                active = false,
            ) => {
                const button = document.createElement("button");

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
                createButton(
                    "‹",
                    currentPage - 1,
                    currentPage <= 1,
                ),
            );

            const start = Math.max(
                1,
                currentPage - 2,
            );

            const end = Math.min(
                pageCount,
                start + 4,
            );

            for (let page = start; page <= end; page += 1) {
                pagination.appendChild(
                    createButton(
                        String(page),
                        page,
                        false,
                        page === currentPage,
                    ),
                );
            }

            pagination.appendChild(
                createButton(
                    "›",
                    currentPage + 1,
                    currentPage >= pageCount,
                ),
            );
        };

        const apply = () => {
            const ordered = sortedRows();

            ordered.forEach(row => {
                body.appendChild(row);
                row.hidden = true;
            });

            const matching = ordered.filter(matchesFilters);
            const pageCount = Math.max(
                1,
                Math.ceil(matching.length / pageSize),
            );

            currentPage = Math.min(
                Math.max(1, currentPage),
                pageCount,
            );

            const start = (
                currentPage - 1
            ) * pageSize;

            const pageRows = matching.slice(
                start,
                start + pageSize,
            );

            pageRows.forEach(row => {
                row.hidden = false;
            });

            if (visibleCount) {
                visibleCount.textContent = String(
                    matching.length,
                );
            }

            if (totalCount) {
                totalCount.textContent = String(
                    rows.length,
                );
            }

            if (emptyState) {
                emptyState.hidden = matching.length > 0;
            }

            renderPagination(pageCount);
        };

        headers.forEach((header, index) => {
            const label = header.textContent.trim();

            if (
                !label
                || index === headers.length - 1
            ) {
                return;
            }

            header.classList.add("sortable-column");
            header.tabIndex = 0;

            const indicator = document.createElement("span");
            indicator.className = "sort-indicator";
            indicator.textContent = "↕";

            header.appendChild(indicator);

            const activate = () => {
                if (sortIndex === index) {
                    sortDirection *= -1;
                } else {
                    sortIndex = index;
                    sortDirection = 1;
                }

                headers.forEach(item => {
                    item.classList.remove(
                        "sorted-ascending",
                        "sorted-descending",
                    );
                });

                header.classList.add(
                    sortDirection === 1
                        ? "sorted-ascending"
                        : "sorted-descending",
                );

                indicator.textContent = (
                    sortDirection === 1
                        ? "↑"
                        : "↓"
                );

                currentPage = 1;
                apply();
            };

            header.addEventListener(
                "click",
                activate,
            );

            header.addEventListener(
                "keydown",
                event => {
                    if (
                        event.key === "Enter"
                        || event.key === " "
                    ) {
                        event.preventDefault();
                        activate();
                    }
                },
            );
        });

        searchInput?.addEventListener("input", () => {
            currentPage = 1;
            apply();
        });

        filters.forEach(filter => {
            filter.addEventListener("change", () => {
                currentPage = 1;
                apply();
            });
        });

        pageSizeSelect?.addEventListener(
            "change",
            () => {
                pageSize = Number(
                    pageSizeSelect.value,
                ) || 10;

                currentPage = 1;
                apply();
            },
        );

        pagination?.addEventListener(
            "click",
            event => {
                const button = event.target.closest(
                    "button[data-page]",
                );

                if (!button || button.disabled) {
                    return;
                }

                currentPage = Number(
                    button.dataset.page,
                ) || 1;

                apply();

                container.scrollIntoView({
                    behavior: "smooth",
                    block: "start",
                });
            },
        );

        exportButton?.addEventListener(
            "click",
            () => {
                const matching = filteredRows();
                const exportHeaders = headers
                    .slice(0, -1)
                    .map(header => (
                        header.childNodes[0]?.textContent
                        || header.textContent
                    ).trim());

                const exportRows = matching.map(row => {
                    return [...row.children]
                        .slice(0, -1)
                        .map(cell => (
                            cell.textContent
                                .replace(/\s+/g, " ")
                                .trim()
                        ));
                });

                const pageName = normalize(
                    document.querySelector("h1")?.textContent
                    || "procsentinel",
                )
                    .replace(/[^a-z0-9]+/g, "-")
                    .replace(/^-|-$/g, "");

                downloadCsv(
                    `${pageName || "procsentinel"}-export.csv`,
                    exportHeaders,
                    exportRows,
                );

                showToast(
                    `${matching.length} records exported`,
                );
            },
        );

        apply();
    };

    document
        .querySelectorAll("[data-table-container]")
        .forEach(initializeTable);
})();
