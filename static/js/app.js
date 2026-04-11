/* IoT Portal - Common JavaScript (jQuery 2.2.4 + Bootstrap 3.3.7) */

// Check authentication
function checkAuth() {
    var user = localStorage.getItem('user');
    if (!user) {
        window.location.href = '/';
        return;
    }
    try {
        var u = JSON.parse(user);
        $('#userName').html('<i class="glyphicon glyphicon-user"></i> ' + u.name + ' (' + u.role + ')');
    } catch(e) {
        window.location.href = '/';
    }
}

// Logout handler
$(document).on('click', '#logoutBtn', function(e) {
    e.preventDefault();
    $.post('/api/logout', function() {
        localStorage.removeItem('user');
        document.cookie = 'session_user=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
        document.cookie = 'user_role=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
        window.location.href = '/';
    });
});

// Dashboard loader
function loadDashboard() {
    $.get('/api/devices', function(devices) {
        var online = 0, offline = 0, warning = 0;
        var html = '';
        devices.forEach(function(d) {
            if (d.status === 'online') online++;
            else if (d.status === 'offline') offline++;
            else warning++;

            var statusClass = d.status === 'online' ? 'success' : d.status === 'offline' ? 'danger' : 'warning';
            html += '<tr>' +
                '<td>' + d.id + '</td>' +
                '<td>' + d.name + '</td>' +
                '<td><span class="label label-default">' + d.type + '</span></td>' +
                '<td>' + d.location + '</td>' +
                '<td><span class="label label-' + statusClass + '">' + d.status + '</span></td>' +
                '<td><code>' + d.ip_address + '</code></td>' +
                '<td>' + d.firmware + '</td>' +
                '<td>' + d.last_seen + '</td>' +
                '</tr>';
        });
        $('#statOnline').text(online);
        $('#statOffline').text(offline);
        $('#statWarning').text(warning);
        $('#statTotal').text(devices.length);
        $('#deviceTableBody').html(html);
    });
}

// Search handler
$(document).on('submit', '#searchForm', function(e) {
    e.preventDefault();
    var q = $('#searchQuery').val();
    if (!q) return;
    $.get('/api/search?q=' + q, function(res) {
        $('#searchQueryDisplay').html(res.query);
        var html = '';
        if (res.results && res.results.length > 0) {
            html = '<table class="table table-condensed"><thead><tr><th>Name</th><th>Type</th><th>Location</th><th>Status</th></tr></thead><tbody>';
            res.results.forEach(function(d) {
                html += '<tr><td>' + d.name + '</td><td>' + d.type + '</td><td>' + d.location + '</td><td>' + d.status + '</td></tr>';
            });
            html += '</tbody></table>';
        } else {
            html = '<p class="text-muted">No devices found matching your query.</p>';
        }
        html += '<p class="text-muted small">Found ' + res.count + ' result(s)</p>';
        $('#searchResultsBody').html(html);
        $('#searchResults').show();
    }).fail(function(xhr) {
        var err = 'Search failed';
        try { err = JSON.parse(xhr.responseText).error; } catch(e) {}
        $('#searchResultsBody').html('<div class="alert alert-danger">' + err + '</div>');
        $('#searchResults').show();
    });
});
