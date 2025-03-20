/**
 * Main JavaScript for Stock Tracker Application
 * Enhanced with security features
 */

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize security features
    initializeSecurity();
    
    // Set up event listeners
    setupEventListeners();
    
    // Load watchlist data
    loadWatchlist();
});

/**
 * Initialize security features
 */
function initializeSecurity() {
    // Get CSRF token from meta tag
    const metaToken = document.querySelector('meta[name="csrf-token"]');
    if (metaToken) {
        csrfToken = metaToken.getAttribute('content');
    }
    
    // Apply input validation to all forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!window.StockTrackerSecurity.validateForm(this)) {
                event.preventDefault();
                event.stopPropagation();
            }
        });
    });
    
    // Add security headers to all AJAX requests
    setupSecureAjax();
}

/**
 * Set up secure AJAX requests
 */
function setupSecureAjax() {
    // Override fetch to add security headers
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {}) {
        // Only add headers to same-origin requests
        if (new URL(url, window.location.origin).origin === window.location.origin) {
            options.headers = options.headers || {};
            options.headers['X-CSRF-Token'] = csrfToken;
            options.headers['X-Requested-With'] = 'XMLHttpRequest';
        }
        return originalFetch.call(this, url, options);
    };
}

/**
 * Set up event listeners for user interactions
 */
function setupEventListeners() {
    // Search button click
    const searchBtn = document.getElementById('searchBtn');
    if (searchBtn) {
        searchBtn.addEventListener('click', function() {
            const symbol = document.getElementById('stockSearch').value.trim().toUpperCase();
            if (window.StockTrackerSecurity.validateInput(document.getElementById('stockSearch'))) {
                loadStockData(symbol);
            }
        });
    }
    
    // Stock search input enter key
    const stockSearch = document.getElementById('stockSearch');
    if (stockSearch) {
        stockSearch.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                const symbol = this.value.trim().toUpperCase();
                if (window.StockTrackerSecurity.validateInput(this)) {
                    loadStockData(symbol);
                }
            }
        });
    }
    
    // Time range selection
    const rangeOptions = document.querySelectorAll('.range-option');
    rangeOptions.forEach(option => {
        option.addEventListener('click', function(e) {
            e.preventDefault();
            const range = this.getAttribute('data-range');
            const symbol = document.getElementById('stockSymbol').textContent;
            if (symbol && symbol !== 'Stock Information') {
                loadStockData(symbol, range);
            }
        });
    });
    
    // Interval selection
    const intervalBtns = document.querySelectorAll('.interval-btn');
    intervalBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const interval = this.getAttribute('data-interval');
            const symbol = document.getElementById('stockSymbol').textContent;
            if (symbol && symbol !== 'Stock Information') {
                updateChartInterval(symbol, interval);
            }
            
            // Update active state
            intervalBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // Add to watchlist button
    const addToWatchlistBtn = document.getElementById('addToWatchlist');
    if (addToWatchlistBtn) {
        addToWatchlistBtn.addEventListener('click', function() {
            const symbol = document.getElementById('stockSymbol').textContent;
            if (symbol && symbol !== 'Stock Information') {
                addToWatchlist(symbol);
            }
        });
    }
}

/**
 * Load stock data for the specified symbol
 * @param {string} symbol - The stock symbol to load
 * @param {string} range - The time range to load (default: '1y')
 */
function loadStockData(symbol, range = '1y') {
    // Sanitize inputs
    symbol = window.StockTrackerSecurity.sanitizeInput(symbol);
    range = window.StockTrackerSecurity.sanitizeInput(range);
    
    // Show loading state
    document.getElementById('stockInfo').innerHTML = '<p class="text-center"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></p>';
    document.getElementById('stockSymbol').textContent = symbol;
    
    // Make secure AJAX request
    window.StockTrackerSecurity.secureAjax(
        `/api/stock/${symbol}?range=${range}`,
        'GET',
        null,
        function(data) {
            if (data.error) {
                document.getElementById('stockInfo').innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
                return;
            }
            
            // Update stock info
            updateStockInfo(data);
            
            // Update chart
            updatePriceChart(data);
            
            // Show stock actions
            document.getElementById('stockActions').classList.remove('d-none');
            
            // Load drops data
            loadDropsData(symbol);
            
            // Load all-time high data
            loadATHData(symbol, range);
        },
        function(error) {
            document.getElementById('stockInfo').innerHTML = `<div class="alert alert-danger">Error loading stock data. Please try again.</div>`;
            console.error('Error loading stock data:', error);
        }
    );
}

/**
 * Update stock information display
 * @param {object} data - The stock data
 */
function updateStockInfo(data) {
    // Sanitize data for display
    const name = window.StockTrackerSecurity.sanitizeInput(data.name || '');
    const symbol = window.StockTrackerSecurity.sanitizeInput(data.symbol || '');
    const currentPrice = data.current_price ? data.current_price.toFixed(2) : 'N/A';
    const change = data.change ? data.change.toFixed(2) : 'N/A';
    const changePercent = data.change_percent ? (data.change_percent * 100).toFixed(2) : 'N/A';
    const volume = data.volume ? data.volume.toLocaleString() : 'N/A';
    const marketCap = data.market_cap ? (data.market_cap / 1000000000).toFixed(2) + 'B' : 'N/A';
    
    // Create HTML with proper escaping
    let html = `
        <h4>${name} (${symbol})</h4>
        <div class="price-container mb-3">
            <span class="current-price">$${currentPrice}</span>
            <span class="price-change ${data.change > 0 ? 'text-success' : 'text-danger'}">
                ${data.change > 0 ? '+' : ''}${change} (${data.change > 0 ? '+' : ''}${changePercent}%)
            </span>
        </div>
        <div class="row">
            <div class="col-6">
                <p><strong>Volume:</strong> ${volume}</p>
                <p><strong>Market Cap:</strong> $${marketCap}</p>
            </div>
            <div class="col-6">
                <p><strong>52-Week High:</strong> $${data.fifty_two_week_high ? data.fifty_two_week_high.toFixed(2) : 'N/A'}</p>
                <p><strong>52-Week Low:</strong> $${data.fifty_two_week_low ? data.fifty_two_week_low.toFixed(2) : 'N/A'}</p>
            </div>
        </div>
    `;
    
    document.getElementById('stockInfo').innerHTML = html;
}

/**
 * Update the price chart with new data
 * @param {object} data - The stock data
 */
function updatePriceChart(data) {
    const ctx = document.getElementById('priceChart').getContext('2d');
    
    // Destroy existing chart if it exists
    if (window.priceChart) {
        window.priceChart.destroy();
    }
    
    // Prepare data for chart
    const labels = data.timestamps.map(ts => new Date(ts * 1000).toLocaleDateString());
    const prices = data.prices;
    const volumes = data.volumes;
    
    // Create gradient for area under line
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, 'rgba(0, 123, 255, 0.4)');
    gradient.addColorStop(1, 'rgba(0, 123, 255, 0.0)');
    
    // Create chart
    window.priceChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Price',
                    data: prices,
                    borderColor: 'rgba(0, 123, 255, 1)',
                    backgroundColor: gradient,
                    borderWidth: 2,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                    pointHoverBackgroundColor: 'rgba(0, 123, 255, 1)',
                    pointHoverBorderColor: 'rgba(0, 123, 255, 1)',
                    fill: true,
                    tension: 0.1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        maxTicksLimit: 10
                    }
                },
                y: {
                    position: 'right',
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        label: function(context) {
                            return `$${context.raw.toFixed(2)}`;
                        }
                    }
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            }
        }
    });
    
    // Add markers for significant drops and all-time highs if available
    if (data.significant_drops) {
        addDropMarkersToChart(data.significant_drops);
    }
    
    if (data.all_time_highs) {
        addATHMarkersToChart(data.all_time_highs);
    }
}

/**
 * Add markers for significant drops to the chart
 * @param {Array} drops - The drops data
 */
function addDropMarkersToChart(drops) {
    if (!window.priceChart || !drops || drops.length === 0) {
        return;
    }
    
    const chart = window.priceChart;
    const chartData = chart.data;
    
    // Create annotation plugin if not exists
    if (!chart.options.plugins.annotation) {
        chart.options.plugins.annotation = {
            annotations: {}
        };
    }
    
    // Add annotations for each drop
    drops.forEach((drop, index) => {
        const dropDate = new Date(drop.date * 1000);
        const labelIndex = chartData.labels.findIndex(label => {
            return new Date(label).toDateString() === dropDate.toDateString();
        });
        
        if (labelIndex !== -1) {
            chart.options.plugins.annotation.annotations[`drop${index}`] = {
                type: 'point',
                xValue: labelIndex,
                yValue: chartData.datasets[0].data[labelIndex],
                backgroundColor: 'rgba(220, 53, 69, 0.8)',
                borderColor: 'rgba(220, 53, 69, 1)',
                borderWidth: 2,
                radius: 5,
                label: {
                    enabled: true,
                    content: `${(drop.percent_change * 100).toFixed(2)}%`,
                    position: 'bottom',
                    backgroundColor: 'rgba(220, 53, 69, 0.8)',
                    color: 'white',
                    font: {
                        size: 10
                    }
                }
            };
        }
    });
    
    chart.update();
}

/**
 * Add markers for all-time highs to the chart
 * @param {Array} highs - The all-time highs data
 */
function addATHMarkersToChart(highs) {
    if (!window.priceChart || !highs || highs.length === 0) {
        return;
    }
    
    const chart = window.priceChart;
    const chartData = chart.data;
    
    // Create annotation plugin if not exists
    if (!chart.options.plugins.annotation) {
        chart.options.plugins.annotation = {
            annotations: {}
        };
    }
    
    // Add annotations for each all-time high
    highs.forEach((high, index) => {
        const highDate = new Date(high.date * 1000);
        const labelIndex = chartData.labels.findIndex(label => {
            return new Date(label).toDateString() === highDate.toDateString();
        });
        
        if (labelIndex !== -1) {
            chart.options.plugins.annotation.annotations[`ath${index}`] = {
                type: 'point',
                xValue: labelIndex,
                yValue: chartData.datasets[0].data[labelIndex],
                backgroundColor: 'rgba(40, 167, 69, 0.8)',
                borderColor: 'rgba(40, 167, 69, 1)',
                borderWidth: 2,
                radius: 5,
                label: {
                    enabled: true,
                    content: 'ATH',
                    position: 'top',
                    backgroundColor: 'rgba(40, 167, 69, 0.8)',
                    color: 'white',
                    font: {
                        size: 10
                    }
                }
            };
        }
    });
    
    chart.update();
}

/**
 * Update chart interval
 * @param {string} symbol - The stock symbol
 * @param {string} interval - The interval to use
 */
function updateChartInterval(symbol, interval) {
    // Sanitize inputs
    symbol = window.StockTrackerSecurity.sanitizeInput(symbol);
    interval = window.StockTrackerSecurity.sanitizeInput(interval);
    
    // Determine appropriate range based on interval
    let range = '1y';
    if (interval === '1d') {
        range = '1mo';
    } else if (interval === '1wk') {
        range = '6mo';
    } else if (interval === '1mo') {
        range = '5y';
    }
    
    // Make secure AJAX request
    window.StockTrackerSecurity.secureAjax(
        `/api/stock/${symbol}?interval=${interval}&range=${range}`,
        'GET',
        null,
        function(data) {
            if (data.error) {
                console.error('Error updating chart interval:', data.error);
                return;
            }
            
            // Update chart
            updatePriceChart(data);
        },
        function(error) {
            console.error('Error updating chart interval:', error);
        }
    );
}

/**
 * Load drops data for the specified symbol
 * @param {string} symbol - The stock symbol
 */
function loadDropsData(symbol) {
    // Sanitize input
    symbol = window.StockTrackerSecurity.sanitizeInput(symbol);
    
    // Make secure AJAX request
    window.StockTrackerSecurity.secureAjax(
        `/api/drops/${symbol}?threshold=-0.03&days=90`,
        'GET',
        null,
        function(data) {
            if (data.error) {
                document.getElementById('dropsContent').innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
                return;
            }
            
            updateDropsContent(data);
        },
        function(error) {
            document.getElementById('dropsContent').innerHTML = `<div class="alert alert-danger">Error loading drops data. Please try again.</div>`;
            console.error('Error loading drops data:', error);
        }
    );
}

/**
 * Update drops content with data
 * @param {object} data - The drops data
 */
function updateDropsContent(data) {
    if (!data.drops || data.drops.length === 0) {
        document.getElementById('dropsContent').innerHTML = '<p class="text-center text-muted">No significant drops detected in the selected time period.</p>';
        return;
    }
    
    let html = '<div class="list-group">';
    
    data.drops.forEach(drop => {
        // Sanitize data for display
        const date = new Date(drop.date * 1000).toLocaleDateString();
        const percentChange = (drop.percent_change * 100).toFixed(2);
        const priceChange = drop.price_change.toFixed(2);
        
        html += `
            <div class="list-group-item">
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">${date}</h6>
                    <span class="text-danger">${percentChange}%</span>
                </div>
                <p class="mb-1">Price dropped $${priceChange} from $${drop.price_before.toFixed(2)} to $${drop.price_after.toFixed(2)}</p>
            </div>
        `;
    });
    
    html += '</div>';
    
    document.getElementById('dropsContent').innerHTML = html;
}

/**
 * Load all-time high data for the specified symbol
 * @param {string} symbol - The stock symbol
 * @param {string} range - The time range to load
 */
function loadATHData(symbol, range) {
    // Sanitize inputs
    symbol = window.StockTrackerSecurity.sanitizeInput(symbol);
    range = window.StockTrackerSecurity.sanitizeInput(range);
    
    // Make secure AJAX request
    window.StockTrackerSecurity.secureAjax(
        `/api/ath/${symbol}?range=${range}`,
        'GET',
        null,
        function(data) {
            if (data.error) {
                document.getElementById('highsContent').innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
                return;
            }
            
            updateATHContent(data);
        },
        function(error) {
            document.getElementById('highsContent').innerHTML = `<div class="alert alert-danger">Error loading all-time high data. Please try again.</div>`;
            console.error('Error loading all-time high data:', error);
        }
    );
}

/**
 * Update all-time high content with data
 * @param {object} data - The all-time high data
 */
function updateATHContent(data) {
    if (!data.all_time_highs || data.all_time_highs.length === 0) {
        document.getElementById('highsContent').innerHTML = '<p class="text-center text-muted">No all-time highs detected in the selected time period.</p>';
        return;
    }
    
    let html = '<div class="list-group">';
    
    data.all_time_highs.forEach(high => {
        // Sanitize data for display
        const date = new Date(high.date * 1000).toLocaleDateString();
        const price = high.price.toFixed(2);
        
        html += `
            <div class="list-group-item">
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">${date}</h6>
                    <span class="text-success">$${price}</span>
                </div>
                <p class="mb-1">New all-time high reached</p>
            </div>
        `;
    });
    
    html += '</div>';
    
    document.getElementById('highsContent').innerHTML = html;
}

/**
 * Load watchlist data
 */
function loadWatchlist() {
    // Make secure AJAX request
    window.StockTrackerSecurity.secureAjax(
        '/api/watchlist',
        'GET',
        null,
        function(data) {
            updateWatchlistTable(data);
        },
        function(error) {
            document.getElementById('watchlistTable').innerHTML = `<tr><td colspan="6" class="text-center text-danger">Error loading watchlist. Please try again.</td></tr>`;
            console.error('Error loading watchlist:', error);
        }
    );
}

/**
 * Update watchlist table with data
 * @param {Array} data - The watchlist data
 */
function updateWatchlistTable(data) {
    if (!data || data.length === 0) {
        document.getElementById('watchlistTable').innerHTML = `<tr><td colspan="6" class="text-center">Your watchlist is empty. Search for stocks to add them.</td></tr>`;
        return;
    }
    
    let html = '';
    
    data.forEach(stock => {
        // Sanitize data for display
        const symbol = window.StockTrackerSecurity.sanitizeInput(stock.symbol);
        const name = window.StockTrackerSecurity.sanitizeInput(stock.name || symbol);
        const currentPrice = stock.current_price ? stock.current_price.toFixed(2) : 'N/A';
        const allTimeHigh = stock.all_time_high ? stock.all_time_high.toFixed(2) : 'N/A';
        const pctFromATH = stock.pct_from_ath ? (stock.pct_from_ath * 100).toFixed(2) : 'N/A';
        
        // Format recent drops
        let dropsHtml = 'None';
        if (stock.significant_drops && stock.significant_drops.length > 0) {
            dropsHtml = stock.significant_drops.map(drop => {
                const date = new Date(drop.date * 1000).toLocaleDateString();
                const pct = (drop.percent_change * 100).toFixed(2);
                return `${date}: ${pct}%`;
            }).join('<br>');
        }
        
        html += `
            <tr>
                <td><a href="#" class="stock-link" data-symbol="${symbol}">${symbol}</a></td>
                <td>$${currentPrice}</td>
                <td>$${allTimeHigh}</td>
                <td>${pctFromATH}%</td>
                <td>${dropsHtml}</td>
                <td>
                    <button class="btn btn-sm btn-danger remove-from-watchlist" data-symbol="${symbol}">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `;
    });
    
    document.getElementById('watchlistTable').innerHTML = html;
    
    // Add event listeners to stock links
    const stockLinks = document.querySelectorAll('.stock-link');
    stockLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const symbol = this.getAttribute('data-symbol');
            loadStockData(symbol);
            
            // Scroll to top
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    });
    
    // Add event listeners to remove buttons
    const removeButtons = document.querySelectorAll('.remove-from-watchlist');
    removeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const symbol = this.getAttribute('data-symbol');
            removeFromWatchlist(symbol);
        });
    });
}

/**
 * Add a stock to the watchlist
 * @param {string} symbol - The stock symbol to add
 */
function addToWatchlist(symbol) {
    // Sanitize input
    symbol = window.StockTrackerSecurity.sanitizeInput(symbol);
    
    // Make secure AJAX request
    window.StockTrackerSecurity.secureAjax(
        '/api/watchlist/add',
        'POST',
        { symbol: symbol, csrf_token: csrfToken },
        function(data) {
            if (data.success) {
                // Show success message
                const alertHtml = `
                    <div class="alert alert-success alert-dismissible fade show" role="alert">
                        ${data.message}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                `;
                document.querySelector('.container').insertAdjacentHTML('afterbegin', alertHtml);
                
                // Reload watchlist
                loadWatchlist();
            } else {
                // Show error message
                const alertHtml = `
                    <div class="alert alert-warning alert-dismissible fade show" role="alert">
                        ${data.message}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                `;
                document.querySelector('.container').insertAdjacentHTML('afterbegin', alertHtml);
            }
        },
        function(error) {
            // Show error message
            const alertHtml = `
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    Error adding to watchlist. Please try again.
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            `;
            document.querySelector('.container').insertAdjacentHTML('afterbegin', alertHtml);
            console.error('Error adding to watchlist:', error);
        }
    );
}

/**
 * Remove a stock from the watchlist
 * @param {string} symbol - The stock symbol to remove
 */
function removeFromWatchlist(symbol) {
    // Sanitize input
    symbol = window.StockTrackerSecurity.sanitizeInput(symbol);
    
    // Make secure AJAX request
    window.StockTrackerSecurity.secureAjax(
        '/api/watchlist/remove',
        'POST',
        { symbol: symbol, csrf_token: csrfToken },
        function(data) {
            if (data.success) {
                // Show success message
                const alertHtml = `
                    <div class="alert alert-success alert-dismissible fade show" role="alert">
                        ${data.message}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                `;
                document.querySelector('.container').insertAdjacentHTML('afterbegin', alertHtml);
                
                // Reload watchlist
                loadWatchlist();
            } else {
                // Show error message
                const alertHtml = `
                    <div class="alert alert-warning alert-dismissible fade show" role="alert">
                        ${data.message}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                `;
                document.querySelector('.container').insertAdjacentHTML('afterbegin', alertHtml);
            }
        },
        function(error) {
            // Show error message
            const alertHtml = `
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    Error removing from watchlist. Please try again.
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            `;
            document.querySelector('.container').insertAdjacentHTML('afterbegin', alertHtml);
            console.error('Error removing from watchlist:', error);
        }
    );
}

// Global CSRF token
let csrfToken = '';
