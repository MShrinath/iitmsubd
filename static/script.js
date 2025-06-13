// Theme handling
let currentTheme = localStorage.getItem('theme') || 'dark';

// Set initial theme
document.documentElement.setAttribute('data-theme', currentTheme);

// Mouse move tracking for card spotlight effect
document.addEventListener('mousemove', (e) => {
    document.documentElement.style.setProperty('--mouse-x', `${e.clientX}px`);
    document.documentElement.style.setProperty('--mouse-y', `${e.clientY}px`);
});

function loadResults() {
    // Show loading state
    const container = document.getElementById("reportSection");
    container.innerHTML = `
        <div class="text-center p-5">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2">Loading domain data...</p>
        </div>
    `;
    
    fetch("/results")
        .then(res => res.json())
        .then(data => {
            renderReport(data);
        })
        .catch(error => {
            container.innerHTML = `
                <div class="alert alert-danger">
                    Error loading results: ${error.message}
                </div>
            `;
        });
}

function renderReport(data) {
    const container = document.getElementById("reportSection");
    container.innerHTML = "";

    let count = data.length;
    let httpsOnly = [];
    let httpOnly = [];
    let expiringSoon = [];
    let noCert = [];
    let totalInvalidCert = 0;
    let totalInvalidCertDomains = [];
    let certExpired = 0;
    let certExpiredDomains = [];

    let countOk = 0;
    let countWarning = 0;
    let countError = 0;

    const now = new Date();

    data.forEach(item => {
        const httpStatus = item.http?.[0];
        const httpsStatus = item.https?.[0];
        const certStatus = item.cert?.[0];
        const certDetails = item.cert_details;
        const certError = certDetails && certDetails.error ? certDetails.error.toLowerCase() : "";
        const isCertExpired = certError.includes("certificate has expired");
        
        if (isCertExpired) {
            certExpired++;
            certExpiredDomains.push(item.domain);
        }

        if (httpsStatus && !httpStatus) httpsOnly.push(item.domain);
        if (httpStatus && !httpsStatus) httpOnly.push(item.domain);

        if (!certStatus) {
            noCert.push(item.domain);
            totalInvalidCert++;
            totalInvalidCertDomains.push(item.domain);
        }
        
        if (certStatus && certDetails?.valid_to) {
            const expiryDate = new Date(certDetails.valid_to);
            const diffDays = (expiryDate - now) / (1000 * 60 * 60 * 24);
            if (diffDays < 30) expiringSoon.push(item.domain);
        }
    
        const httpOk = httpStatus === 200;
        const httpsOk = httpsStatus === 200;
        const notExpiring = certDetails?.valid_to ? ((new Date(certDetails.valid_to) - now) / (1000 * 60 * 60 * 24) >= 30) : false;
        
        // if (httpOk && httpsOk && certStatus && !isCertExpired && notExpiring) {
        //     countOk++;
        // } else if (isCertExpired) {
        //     countError++;
        // } else {
        //     countWarning++;
        // }
    });

    // Update inline count beside heading
    document.getElementById("domainCount").textContent = count;

    // Chart Container
    const chartContainer = document.createElement("div");
    chartContainer.className = "mb-4";
    chartContainer.innerHTML = `
        <div class="row g-4 align-items-center">
            <div class="col-md-8">
                <div class="row g-3 mb-4">
                    <div class="col-md-4">
                        <div class="card text-bg-light border-danger h-100">
                            <div class="card-body">
                                <h5 class="card-title">🔔 Certificates Expiring Soon</h5>
                                <p class="fs-4 fw-semibold">${expiringSoon.length}</p>
                                ${renderDomainPopupButton(expiringSoon, "Expiring Soon Domains")}
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card text-bg-light border-warning h-100">
                            <div class="card-body">
                                <h5 class="card-title">🌐 HTTP Service Unavailable</h5>
                                <p class="fs-4 fw-semibold">${httpsOnly.length}</p>
                                ${renderDomainPopupButton(httpsOnly, "No HTTP Domains", "https")}
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card text-bg-light border-warning h-100">
                            <div class="card-body">
                                <h5 class="card-title">🔓 Insecure (HTTP Only)</h5>
                                <p class="fs-4 fw-semibold">${httpOnly.length}</p>
                                ${renderDomainPopupButton(httpOnly, "HTTP Only Domains", "http")}
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card text-bg-light border-danger h-100">
                            <div class="card-body">
                                <h5 class="card-title">🛑 Certificate Expired</h5>
                                <p class="fs-4 fw-semibold">${certExpired}</p>
                                ${renderDomainPopupButton(certExpiredDomains, "Expired Certificate Domains", "http")}
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card text-bg-light border-warning h-100">
                            <div class="card-body">
                                <h5 class="card-title">🔐 Certificate Verification Failed</h5>
                                <p class="fs-4 fw-semibold">${totalInvalidCert}</p>
                                ${renderDomainPopupButton(totalInvalidCertDomains, "Invalid Certificate Domains", "http")}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h5 class="card-title">Domain Status</h5>
                        <div class="chart-container">
                            <canvas id="certDonutChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    container.appendChild(chartContainer);

    // Domains grid
    const domainsTitle = document.createElement("h3");
    domainsTitle.className = "mb-3 mt-4";
    domainsTitle.innerHTML = `Domain Status <span class="badge bg-secondary">${count}</span>`;
    container.appendChild(domainsTitle);
    
    // Search bar
    const searchBar = document.createElement("div");
    searchBar.className = "mb-4";
    searchBar.innerHTML = `
        <div class="input-group">
            <span class="input-group-text">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-search" viewBox="0 0 16 16">
                    <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001c.03.04.062.078.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z"/>
                </svg>
            </span>
            <input type="text" class="form-control" id="domainSearch" placeholder="Search domains...">
        </div>
    `;
    container.appendChild(searchBar);

    // Filter buttons
    const filterButtons = document.createElement("div");
    filterButtons.className = "mb-4 btn-group";
    filterButtons.innerHTML = `
        <button class="btn btn-outline-secondary active" data-filter="all">All</button>
        <button class="btn btn-outline-success" data-filter="ok">OK</button>
        <button class="btn btn-outline-warning" data-filter="warning">Warnings</button>
        <button class="btn btn-outline-danger" data-filter="error">Errors</button>
    `;
    container.appendChild(filterButtons);


    const statusLegend = document.createElement("div");
    statusLegend.className = "mb-4";

    statusLegend.innerHTML = `
    <div class="card shadow-sm status-legend">
        <div class="card-body">
        <div class="row g-3">
            <div class="col-md-4">
            <div class="d-flex align-items-center">
                <span class="badge bg-success me-3" style="width: 2.2rem; height: 2.2rem; display: flex; align-items: center; justify-content: center;">✅</span>
                <div>
                <strong>OK</strong><br>
                All checks passed: HTTP/HTTPS responses are 200, certificate is valid & not expiring soon.
                </div>
            </div>
            </div>
            <div class="col-md-4">
            <div class="d-flex align-items-center">
                <span class="badge bg-warning text-dark me-3" style="width: 2.2rem; height: 2.2rem; display: flex; align-items: center; justify-content: center;">⚠️</span>
                <div>
                <strong>Warning</strong><br>
                One or more issues: non-200 responses or certificate expiring soon.
                </div>
            </div>
            </div>
            <div class="col-md-4">
            <div class="d-flex align-items-center">
                <span class="badge bg-danger me-3" style="width: 2.2rem; height: 2.2rem; display: flex; align-items: center; justify-content: center;">❌</span>
                <div>
                <strong>Error</strong><br>
                Certificate is missing or invalid, HTTPS is broken.
                </div>
            </div>
            </div>
        </div>
        </div>
    </div>
    `;

    container.appendChild(statusLegend);



    // Setup filter functionality
    filterButtons.querySelectorAll('button').forEach(btn => {
        btn.addEventListener('click', (e) => {
            // Remove active class from all buttons
            filterButtons.querySelectorAll('button').forEach(b => 
                b.classList.remove('active'));
            
            // Add active class to clicked button
            e.target.classList.add('active');
            
            // Get filter value
            const filter = e.target.getAttribute('data-filter');
            
            // Apply filter
            const cards = document.querySelectorAll('.domain-card');
            cards.forEach(card => {
                if (filter === 'all') {
                    card.style.display = '';
                } else {
                    if (card.classList.contains(filter)) {
                        card.style.display = '';
                    } else {
                        card.style.display = 'none';
                    }
                }
            });
        });
    });

    // Setup search functionality
    document.getElementById('domainSearch').addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        const cards = document.querySelectorAll('.domain-card');
        
        cards.forEach(card => {
            const domain = card.getAttribute('data-domain').toLowerCase();
            if (domain.includes(searchTerm)) {
                card.style.display = '';
            } else {
                card.style.display = 'none';
            }
        });
    });

    const row = document.createElement("div");
    row.className = "row g-4";

    data.forEach(item => {
        let domainClass = "border-success";
        let statusClass = "ok";
        let statusOk = true;

        const httpStatus = item.http?.[0];
        const httpsStatus = item.https?.[0];
        const certStatus = item.cert?.[0];
        const certDetails = item.cert_details;
        
        const httpOk = httpStatus === 200;
        const httpsOk = httpsStatus === 200;
        const certOk = certStatus === true;
        const notExpiring = certDetails?.valid_to 
            ? (new Date(certDetails.valid_to) - new Date()) / (1000 * 60 * 60 * 24) >= 30
            : false;

        // Default: assume OK, override if not
        if (!httpOk || !httpsOk) {
            domainClass = "border-warning";
            statusClass = "warning";
            statusOk = false;
        }

        // Cert is missing or invalid = ERROR
        if (!certOk) {
            domainClass = "border-danger";
            statusClass = "error";
            statusOk = false;
        }

        // Cert valid but expiring soon = WARNING
        if (certOk && !notExpiring) {
            domainClass = "border-warning";
            statusClass = "warning";
            statusOk = false;
        }

        // Final check: all must be good for OK
        if (httpOk && httpsOk && certOk && notExpiring) {
            domainClass = "border-success";
            statusClass = "ok";
            statusOk = true;
        }

        // final countok countwarning counterror
        if (statusClass === "ok") {
            countOk++;
        }
        else if (statusClass === "warning") {
            countWarning++;
        }
        else if (statusClass === "error") {
            countError++;
        }

        const col = document.createElement("div");
        col.className = "col-md-6 col-lg-4 domain-card " + statusClass;
        col.setAttribute('data-domain', item.domain);

        const card = document.createElement("div");
        card.className = `card h-100 ${domainClass}`;
        card.innerHTML = `
            <div class="card-body" id="card-${item.domain.replace(/\W/g, '-')}" data-domain="${item.domain}">
                <h5 class="card-title d-flex align-items-center">
                    <span class="status-icon me-2">${statusOk ? "✅" : "⚠️"}</span>
                    <span class="domain-name">${formatDomainName(item.domain)}</span>
                </h5>
                <h6 class="card-subtitle mb-2 text-muted d-flex align-items-center">
                    <span class="badge domain-badge me-2">${item.ip?.join(", ") || "N/A"}</span>
                </h6>
                <div class="mt-3">
                    <div class="d-flex justify-content-between mb-2 align-items-center">
                        <strong>HTTP:</strong> 
                        ${renderHttpStatus(item.http)}
                    </div>
                    <div class="d-flex justify-content-between mb-2 align-items-center">
                        <strong>HTTPS:</strong> 
                        ${renderHttpStatus(item.https)}
                    </div>
                    <div class="d-flex justify-content-between mb-3 align-items-center">
                        <strong>Certificate:</strong> 
                        ${renderCertStatus(item.cert)}
                    </div>
                </div>
                <div class="d-flex mt-3">
                    <a href="https://${item.domain}" target="_blank" class="btn btn-sm btn-outline-primary me-2">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-box-arrow-up-right" viewBox="0 0 16 16">
                            <path fill-rule="evenodd" d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"/>
                            <path fill-rule="evenodd" d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"/>
                        </svg>
                        Visit
                    </a>
                    ${item.cert_details ? `
                    <button class="btn btn-sm btn-outline-info cert-details-btn">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-lock" viewBox="0 0 16 16">
                            <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.725 10.725 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.615.615 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.775 11.775 0 0 1-2.517 2.453 7.159 7.159 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7.158 7.158 0 0 1-1.048-.625 11.777 11.777 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 62.456 62.456 0 0 1 5.072.56z"/>
                            <path d="M9.5 6.5a1.5 1.5 0 0 1-1 1.415l.385 1.99a.5.5 0 0 1-.491.595h-.788a.5.5 0 0 1-.49-.595l.384-1.99a1.5 1.5 0 1 1 2-1.415z"/>
                        </svg>
                        Certificate
                    </button>` : ''}
                    ${item.ip && item.ip.length > 0 ? `
                    <button class="btn btn-sm btn-outline-warning nmap-btn" data-ip="${item.ip[0]}">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-radar" viewBox="0 0 16 16">
                            <path d="M6.634 1.135A7 7 0 0 1 15 8a.5.5 0 0 1-1 0 6 6 0 1 0-6.5 5.98v-1.005A5 5 0 1 1 13 8a.5.5 0 0 1-1 0 4 4 0 1 0-4.5 3.969v-1.011A2.999 2.999 0 1 1 11 8a.5.5 0 0 1-1 0 2 2 0 1 0-2.5 1.936v-.998A1 1 0 1 1 9 8a.5.5 0 0 1-1 0 .5.5 0 0 0-1-1v5.5a.5.5 0 0 1-1 0V8a1.5 1.5 0 1 1 1.5-1.5"/>
                        </svg>
                        Nmap
                    </button>` : ''}
                </div>
            </div>
        `;

        if (item.cert_details) {
            card.querySelector('.cert-details-btn').addEventListener("click", () => showCertModal(item.cert_details));
        }
        // Add Nmap button functionality
        const nmapBtn = card.querySelector('.nmap-btn');
        if (item) {
            nmapBtn.addEventListener("click", () => runNmap(item.ip[0], item.domain));
        }

        col.appendChild(card);
        row.appendChild(col);
    });

    container.appendChild(row);

    // Initialize Chart
    renderCertChart(countOk, countWarning, countError);

    // Add theme toggle to header
    if (!document.querySelector('.theme-toggle')) {
        const header = document.querySelector('header');
        const themeToggle = document.createElement('button');
        themeToggle.className = 'theme-toggle';
        themeToggle.setAttribute('aria-label', 'Toggle dark mode');
        themeToggle.innerHTML = currentTheme === 'dark' 
            ? '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 18C8.68629 18 6 15.3137 6 12C6 8.68629 8.68629 6 12 6C15.3137 6 18 8.68629 18 12C18 15.3137 15.3137 18 12 18ZM12 16C14.2091 16 16 14.2091 16 12C16 9.79086 14.2091 8 12 8C9.79086 8 8 9.79086 8 12C8 14.2091 9.79086 16 12 16ZM11 1H13V4H11V1ZM11 20H13V23H11V20ZM3.51472 4.92893L4.92893 3.51472L7.05025 5.63604L5.63604 7.05025L3.51472 4.92893ZM16.9497 18.364L18.364 16.9497L20.4853 19.0711L19.0711 20.4853L16.9497 18.364ZM19.0711 3.51472L20.4853 4.92893L18.364 7.05025L16.9497 5.63604L19.0711 3.51472ZM5.63604 16.9497L7.05025 18.364L4.92893 20.4853L3.51472 19.0711L5.63604 16.9497ZM23 11V13H20V11H23ZM4 11V13H1V11H4Z"></path></svg>'
            : '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M10 7C10 10.866 13.134 14 17 14C18.9584 14 20.729 13.1957 21.9995 11.8995C22 11.933 22 11.9665 22 12C22 17.5228 17.5228 22 12 22C6.47715 22 2 17.5228 2 12C2 6.47715 6.47715 2 12 2C12.0335 2 12.067 2 12.1005 2.00049C10.8043 3.27105 10 5.04157 10 7ZM4 12C4 16.4183 7.58172 20 12 20C15.0583 20 17.7158 18.2839 19.062 15.7621C18.3945 15.9196 17.7035 16 17 16C12.0294 16 8 11.9706 8 7C8 6.29648 8.08036 5.60547 8.2379 4.938C5.71611 6.28423 4 8.9417 4 12Z"></path></svg>';
        
        themeToggle.addEventListener('click', toggleTheme);
        header.appendChild(themeToggle);
    }
}

function formatDomainName(domain) {
    // Try to fetch a favicon
    return `
        <div class="domain-display">
            <div class="favicon-wrapper">
                <img src="https://${domain}/favicon.ico" onerror="this.onerror=null;this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%2216%22 height=%2216%22 viewBox=%220 0 24 24%22><path fill=%22%23aaa%22 d=%22M12 7V3H2v18h20V7H12zM6 19H4v-2h2v2zm0-4H4v-2h2v2zm0-4H4V9h2v2zm0-4H4V5h2v2zm4 12H8v-2h2v2zm0-4H8v-2h2v2zm0-4H8V9h2v2zm0-4H8V5h2v2zm10 12h-8v-2h2v-2h-2v-2h2v-2h-2V9h8v10zm-2-8h-2v2h2v-2zm0 4h-2v2h2v-2z%22/></svg>';" alt="${domain}">
            </div>
            <a href="https://${domain}" target="_blank" class="domain-link">${domain}</a>
        </div>
    `;
}

function renderHttpStatus(httpArray) {
    if (!httpArray || httpArray.length < 1 || httpArray[0] == null)
        return `<span class="badge bg-secondary">No Response</span>`;
    
    const code = httpArray[0];
    let badgeClass = 'bg-success';
    let icon = '✅';
    
    if (code !== 200) {
        badgeClass = 'bg-danger';
        icon = '❌';
    }
    
    return `<span class="badge ${badgeClass}">${icon} ${code}</span>`;
}

function renderCertStatus(certArray) {
    if (!certArray) return `<span class="badge bg-secondary">Unknown</span>`;
    
    const valid = certArray[0];
    if (valid) {
        // Parse the date to check if it's expiring soon
        const expiryDate = new Date(certArray[1]);
        const now = new Date();
        const diffDays = (expiryDate - now) / (1000 * 60 * 60 * 24);
        
        let badgeClass = 'bg-success';
        let icon = '🔒';
        let formattedDate = new Date(certArray[1]).toLocaleDateString();
        
        if (diffDays < 30) {
            badgeClass = 'bg-warning';
            icon = '⚠️';
        }
        
        return `<span class="badge ${badgeClass}">${icon} ${formattedDate}</span>`;
    } else {
        return `<span class="badge bg-danger">❌ Missing</span>`;
    }
}

function renderDomainPopupButton(domains, title, proto = "https") {
    if (domains.length === 0) return "";

    const buttonId = title.replace(/\s+/g, "") + "Btn";
    return `
        <button class="btn btn-sm btn-outline-secondary mt-2" type="button"
                onclick='showDomainList(${JSON.stringify(domains)}, "${title}", "${proto}")'>
            View Domains (${domains.length})
        </button>
    `;
}

function showDomainList(domains, title, proto = "https") {
    const modal = new bootstrap.Modal(document.getElementById("domainListModal"));
    const modalTitle = document.getElementById("domainListTitle");
    const modalBody = document.getElementById("domainListBody");

    modalTitle.textContent = title;
    modalBody.innerHTML = `
        <div class="input-group mb-3">
            <span class="input-group-text">Filter</span>
            <input type="text" class="form-control" id="domainListFilter" placeholder="Type to filter...">
        </div>
        <ul class="list-group domain-list">
            ${domains.map(domain => `
                <li class="list-group-item d-flex justify-content-between align-items-center">
                    <a href="#" onclick="scrollToDomain('${domain}'); return false;">${domain}</a>
                    <a href="${proto}://${domain}" target="_blank" class="btn btn-sm btn-outline-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-box-arrow-up-right" viewBox="0 0 16 16">
                            <path fill-rule="evenodd" d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"/>
                            <path fill-rule="evenodd" d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"/>
                        </svg>
                    </a>
                </li>
            `).join("")}
        </ul>
    `;

    // Add filter functionality
    setTimeout(() => {
        const filterInput = document.getElementById('domainListFilter');
        if (filterInput) {
            filterInput.focus();
            filterInput.addEventListener('input', (e) => {
                const filterValue = e.target.value.toLowerCase();
                const items = document.querySelectorAll('.domain-list .list-group-item');
                
                items.forEach(item => {
                    const domainText = item.textContent.toLowerCase();
                    if (domainText.includes(filterValue)) {
                        item.style.display = '';
                    } else {
                        item.style.display = 'none';
                    }
                });
            });
        }
    }, 300);

    modal.show();
}

function scrollToDomain(domain) {
    const id = `card-${domain.replace(/\W/g, '-')}`;
    const el = document.getElementById(id);

    // Close the popup/modal if open
    const summaryModalEl = document.getElementById("domainListModal");
    const summaryModal = bootstrap.Modal.getInstance(summaryModalEl);
    if (summaryModal) summaryModal.hide();

    // Scroll and highlight
    if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });

        el.classList.add("border-3", "border-info");
        el.style.transition = "box-shadow 0.4s ease";
        el.style.boxShadow = "0 0 0.5rem 0.2rem rgba(13, 110, 253, 0.6)";

        setTimeout(() => {
            el.classList.remove("border-3", "border-info");
            el.style.boxShadow = "";
        }, 2000);
    }
}

function runNmap(ip, domain) {
    // Show loading state on the button
    const nmapBtn = document.querySelector(`[data-ip="${ip}"]`);
    const originalText = nmapBtn.innerHTML;
    nmapBtn.innerHTML = `
        <div class="spinner-border spinner-border-sm me-1" role="status">
            <span class="visually-hidden">Loading...</span>
        </div>
        Running...
    `;
    nmapBtn.disabled = true;

    showNmapModal({
        output: `
            <div class="d-flex align-items-center gap-2">
                <div class="spinner-border text-info spinner-border-sm" role="status"></div>
                <span>Scan running...</span>
            </div>
        `
    }, ip, domain);

    fetch(`/nmap/${ip}`)
        .then(response => response.text())
        .then(text => {
            if (text.trim().length > 0) {
                showNmapModal({ output: text }, ip, domain);
            } else {
                showNmapModal({ error: "No output from Nmap." }, ip, domain);
            }
        })
        .catch(error => {
            console.error('Nmap error:', error);
            showNmapModal({ error: error.message }, ip, domain);
        })
        .finally(() => {
            nmapBtn.innerHTML = originalText;
            nmapBtn.disabled = false;
        });

}

const nmapModalInstance = new bootstrap.Modal(document.getElementById("nmapModal"));
let nmapModalShown = false;

function showNmapModal(nmapData, ip = "N/A", domain = "N/A") {
    const modalTitle = document.getElementById("nmapModalTitle");
    const modalBody = document.getElementById("nmapModalBody");

    modalTitle.textContent = `Nmap Results for ${domain} (${ip})`;

    if (nmapData.error) {
        modalBody.innerHTML = `
            <div class="alert alert-danger">
                <h5>❌ Error running Nmap</h5>
                <p>${nmapData.error}</p>
            </div>
        `;
    } else {
        modalBody.innerHTML = `
            <div class="nmap-results">
                <div class="mb-3">
                    <h6>Target Information</h6>
                    <div class="bg-dark p-3 rounded">
                        <div class="text-info">Domain: <span class="text-white">${domain}</span></div>
                        <div class="text-info">IP Address: <span class="text-white">${ip}</span></div>
                    </div>
                </div>
                
                <div class="mb-3">
                    <h6>Scan Results</h6>
                    <pre class="bg-dark text-light p-3 rounded" style="max-height: 400px; overflow-y: auto; font-family: 'Courier New', monospace; font-size: 0.9em;">${nmapData.output}</pre>
                </div>
                
                <div class="d-flex gap-2">
                    <button class="btn btn-sm btn-outline-secondary" onclick="copyNmapResults('${ip}')">
                        📋 Copy Results
                    </button>
                    <button class="btn btn-sm btn-outline-info" onclick="runNmap('${ip}', '${domain}')">
                        🔄 Re-run Scan
                    </button>
                </div>
            </div>
        `;
    }

    if (!nmapModalShown) {
        nmapModalInstance.show();
        nmapModalShown = true;
    }
}
// Handle modal close event to reset state
document.getElementById("nmapModal").addEventListener("hidden.bs.modal", () => {
    nmapModalShown = false;
});


function copyNmapResults(ip) {
    const resultsElement = document.querySelector('.nmap-results pre');
    if (resultsElement) {
        navigator.clipboard.writeText(resultsElement.textContent)
            .then(() => {
                // Create toast notification
                const toast = document.createElement('div');
                toast.className = 'position-fixed top-0 end-0 p-3';
                toast.style.zIndex = '1070';
                toast.innerHTML = `
                    <div class="toast show" role="alert" aria-live="assertive" aria-atomic="true">
                        <div class="toast-header">
                            <strong class="me-auto">✅ Success</strong>
                            <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
                        </div>
                        <div class="toast-body">
                            Nmap results copied to clipboard!
                        </div>
                    </div>
                `;
                document.body.appendChild(toast);
                
                // Auto remove after 3 seconds
                setTimeout(() => {
                    toast.remove();
                }, 3000);
            })
            .catch(() => alert("❌ Failed to copy results."));
    }
}

function showCertModal(cert) {
    const modal = new bootstrap.Modal(document.getElementById("certModal"));
    const certBody = document.getElementById("certDetails");

    if (!cert) {
        certBody.innerHTML = `<div class="text-danger">No certificate info available.</div>`;
        modal.show();
        return;
    }

    if (cert.error) {
        certBody.innerHTML = `
            <div class="text-danger">
                ❌ Error retrieving certificate:<br>
                <code>${cert.error}</code>
            </div>
        `;
        modal.show();
        return;
    }

    const now = new Date();
    const validToDate = new Date(cert.valid_to);
    let validityClass = "text-success";

    if (validToDate < now) {
        validityClass = "text-danger"; // expired
    } else if ((validToDate - now) / (1000 * 60 * 60 * 24) < 30) {
        validityClass = "text-warning"; // expiring soon
    }

    // Create a more modern certificate display
    let content = `
        <div class="certificate-display">
            <div class="cert-header mb-4">
                <h4 class="text-info">${cert.subject_common_name}</h4>
                <div class="cert-status ${validToDate < now ? 'expired' : 'valid'}">
                    ${validToDate < now ? '❌ Expired' : '✅ Valid'}
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6">
                    <div class="cert-field mb-3">
                        <div class="cert-label">Issuer</div>
                        <div class="cert-value">${cert.issuer_common_name || "N/A"}</div>
                    </div>
                    
                    <div class="cert-field mb-3">
                        <div class="cert-label">Valid From</div>
                        <div class="cert-value text-success">${formatDate(cert.valid_from)}</div>
                    </div>
                    
                    <div class="cert-field mb-3">
                        <div class="cert-label">Valid To</div>
                        <div class="cert-value ${validityClass}">${formatDate(cert.valid_to)}</div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="cert-field mb-3">
                        <div class="cert-label">Serial Number</div>
                        <div class="cert-value font-monospace">${cert.serial_number || "N/A"}</div>
                    </div>
                    
                    <div class="cert-field">
                        <div class="cert-label">Alternative Names</div>
                        <div class="cert-value alt-names">
                            ${renderAltNames(cert.full_raw?.subjectAltName)}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Raw JSON + Copy Button
    const rawJSON = JSON.stringify(cert, null, 2);
    content += `
        <div class="mt-4 pt-3 border-top">
            <button class="btn btn-sm btn-outline-secondary me-2" type="button" data-bs-toggle="collapse" data-bs-target="#rawCertCollapse">
                🔍 Show Raw
            </button>
            <button class="btn btn-sm btn-outline-dark" onclick="copyRawCertJSON()">📋 Copy Raw to Clipboard</button>

            <div class="collapse mt-2" id="rawCertCollapse">
                <pre id="rawCertData" style="background-color: var(--bg-secondary); padding: 1em; border: 1px solid var(--border-color); max-height: 300px; overflow-y: auto;">${rawJSON}</pre>
            </div>
        </div>
    `;

    certBody.innerHTML = content;
    modal.show();
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function renderAltNames(altNamesArray) {
    if (!altNamesArray || !Array.isArray(altNamesArray) || altNamesArray.length === 0) {
        return '<span class="text-muted">None</span>';
    }
    
    const names = altNamesArray.map(alt => alt[1]);
    if (names.length <= 3) {
        return names.map(name => `<span class="badge bg-light text-dark mb-1 me-1">${name}</span>`).join(' ');
    } else {
        const visibleNames = names.slice(0, 3);
        const hiddenCount = names.length - 3;
        
        return `
            ${visibleNames.map(name => `<span class="badge bg-light text-dark mb-1 me-1">${name}</span>`).join(' ')}
            <button class="btn btn-sm btn-link p-0" 
                    type="button" 
                    data-bs-toggle="collapse" 
                    data-bs-target="#moreAltNames">
                +${hiddenCount} more
            </button>
            <div class="collapse mt-1" id="moreAltNames">
                ${names.slice(3).map(name => `<span class="badge bg-light text-dark mb-1 me-1">${name}</span>`).join(' ')}
            </div>
        `;
    }
}

// Theme toggle function
function toggleTheme() {
    currentTheme = currentTheme === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', currentTheme);
    localStorage.setItem('theme', currentTheme);
    
    // Update toggle icon
    const themeToggle = document.querySelector('.theme-toggle');
    if (themeToggle) {
        themeToggle.innerHTML = currentTheme === 'dark' 
            ? '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 18C8.68629 18 6 15.3137 6 12C6 8.68629 8.68629 6 12 6C15.3137 6 18 8.68629 18 12C18 15.3137 15.3137 18 12 18ZM12 16C14.2091 16 16 14.2091 16 12C16 9.79086 14.2091 8 12 8C9.79086 8 8 9.79086 8 12C8 14.2091 9.79086 16 12 16ZM11 1H13V4H11V1ZM11 20H13V23H11V20ZM3.51472 4.92893L4.92893 3.51472L7.05025 5.63604L5.63604 7.05025L3.51472 4.92893ZM16.9497 18.364L18.364 16.9497L20.4853 19.0711L19.0711 20.4853L16.9497 18.364ZM19.0711 3.51472L20.4853 4.92893L18.364 7.05025L16.9497 5.63604L19.0711 3.51472ZM5.63604 16.9497L7.05025 18.364L4.92893 20.4853L3.51472 19.0711L5.63604 16.9497ZM23 11V13H20V11H23ZM4 11V13H1V11H4Z"></path></svg>'
            : '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M10 7C10 10.866 13.134 14 17 14C18.9584 14 20.729 13.1957 21.9995 11.8995C22 11.933 22 11.9665 22 12C22 17.5228 17.5228 22 12 22C6.47715 22 2 17.5228 2 12C2 6.47715 6.47715 2 12 2C12.0335 2 12.067 2 12.1005 2.00049C10.8043 3.27105 10 5.04157 10 7ZM4 12C4 16.4183 7.58172 20 12 20C15.0583 20 17.7158 18.2839 19.062 15.7621C18.3945 15.9196 17.7035 16 17 16C12.0294 16 8 11.9706 8 7C8 6.29648 8.08036 5.60547 8.2379 4.938C5.71611 6.28423 4 8.9417 4 12Z"></path></svg>';
    }
    
    // Update chart if it exists
    const chart = Chart.getChart("certDonutChart");
    if (chart) {
        updateChartColors(chart);
    }
}

function renderCertChart(countOk, countWarning, countError) {
    // Get the chart context
    const ctx = document.getElementById('certDonutChart');
    if (!ctx) return;
    
    // Check if chart already exists and destroy it
    const existingChart = Chart.getChart(ctx);
    if (existingChart) {
        existingChart.destroy();
    }
    
    // Chart.js configuration
    const certChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['OK', 'WARNING', 'ERROR'],
            datasets: [{
                data: [countOk, countWarning, countError],
                backgroundColor: [
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-success'),
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-warning'),
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-danger')
                ],
                borderColor: [
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-success'),
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-warning'),
                    getComputedStyle(document.documentElement).getPropertyValue('--chart-danger')
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: getComputedStyle(document.documentElement).getPropertyValue('--text-primary'),
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: false
                }
            },
            cutout: '70%',
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });
}

function updateChartColors(chart) {
    chart.data.datasets[0].backgroundColor = [
        getComputedStyle(document.documentElement).getPropertyValue('--chart-success'),
        getComputedStyle(document.documentElement).getPropertyValue('--chart-warning'),
        getComputedStyle(document.documentElement).getPropertyValue('--chart-danger')
    ];
    chart.data.datasets[0].borderColor = [
        getComputedStyle(document.documentElement).getPropertyValue('--chart-success'),
        getComputedStyle(document.documentElement).getPropertyValue('--chart-warning'),
        getComputedStyle(document.documentElement).getPropertyValue('--chart-danger')
    ];
    
    chart.options.plugins.legend.labels.color = 
        getComputedStyle(document.documentElement).getPropertyValue('--text-primary');
    
    chart.update();
}

// Clipboard copy function
function copyRawCertJSON() {
    const raw = document.getElementById("rawCertData");
    if (!raw) return;
    navigator.clipboard.writeText(raw.textContent)
        .then(() => {
            // Create toast notification
            const toast = document.createElement('div');
            toast.className = 'position-fixed top-0 end-0 p-3';
            toast.style.zIndex = '1070';
            toast.innerHTML = `
                <div class="toast show" role="alert" aria-live="assertive" aria-atomic="true">
                    <div class="toast-header">
                        <strong class="me-auto">✅ Success</strong>
                        <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
                    </div>
                    <div class="toast-body">
                        Certificate data copied to clipboard!
                    </div>
                </div>
            `;
            document.body.appendChild(toast);
            
            // Auto remove after 3 seconds
            setTimeout(() => {
                toast.remove();
            }, 3000);
        })
        .catch(() => alert("❌ Failed to copy."));
}

document.getElementById("rescanBtn").addEventListener("click", () => {
    if (!confirm("Do you want to re-scan iitm.ac.in?")) return;

    const modal = new bootstrap.Modal(document.getElementById("scanModal"));
    const logBox = document.getElementById("scanLog");
    logBox.textContent = "Starting scan...\n";
    modal.show();

    const source = new EventSource("/rescan/stream");

    source.onmessage = function (event) {
        logBox.textContent += event.data + "\n";
        logBox.scrollTop = logBox.scrollHeight;

        if (event.data.startsWith("✅ Rescan complete")) {
            source.close();
            setTimeout(() => {
                modal.hide();
                loadResults();
            }, 1500);
        }
    };
});

// Initialize on page load
loadResults();