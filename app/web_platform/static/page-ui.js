(() => {
    const normalize = value => String(value || "").trim().toLowerCase();

    const applyTableFilters = container => {
        const searchInput = container.querySelector("[data-table-search]");
        const filters = [...container.querySelectorAll("[data-table-filter]")];
        const rows = [...container.querySelectorAll("[data-table-row]")];
        const empty = container.querySelector("[data-table-empty]");
        const search = normalize(searchInput?.value);

        let visible = 0;

        rows.forEach(row => {
            const searchable = normalize(
                row.dataset.search || row.textContent,
            );

            const matchesSearch = !search || searchable.includes(search);

            const matchesFilters = filters.every(filter => {
                const value = normalize(filter.value);

                if (!value) {
                    return true;
                }

                const key = filter.dataset.tableFilter;
                return normalize(row.dataset[key]) === value;
            });

            const show = matchesSearch && matchesFilters;

            row.hidden = !show;

            if (show) {
                visible += 1;
            }
        });

        if (empty) {
            empty.hidden = visible > 0;
        }
    };

    const initializeTables = () => {
        const containers = [
            ...document.querySelectorAll("[data-table-container]"),
        ];

        containers.forEach(container => {
            const inputs = [
                ...container.querySelectorAll(
                    "[data-table-search], [data-table-filter]",
                ),
            ];

            inputs.forEach(input => {
                input.addEventListener(
                    input.matches("select") ? "change" : "input",
                    () => applyTableFilters(container),
                );
            });

            applyTableFilters(container);
        });

        const globalSearch = document.querySelector(
            ".topbar-search input",
        );

        const localSearch = document.querySelector(
            "[data-table-search]",
        );

        if (globalSearch && localSearch) {
            globalSearch.addEventListener("input", () => {
                localSearch.value = globalSearch.value;
                localSearch.dispatchEvent(
                    new Event("input", { bubbles: true }),
                );
            });

            localSearch.addEventListener("input", () => {
                globalSearch.value = localSearch.value;
            });
        }
    };

    const initializeRefresh = () => {
        document
            .querySelectorAll("[data-page-refresh]")
            .forEach(button => {
                button.addEventListener("click", () => {
                    button.disabled = true;
                    window.location.reload();
                });
            });
    };

    const initializeConfirmations = () => {
        document
            .querySelectorAll("form[data-confirm]")
            .forEach(form => {
                form.addEventListener("submit", event => {
                    const message = form.dataset.confirm;

                    if (!window.confirm(message)) {
                        event.preventDefault();
                    }
                });
            });
    };

    initializeTables();
    initializeRefresh();
    initializeConfirmations();
})();
