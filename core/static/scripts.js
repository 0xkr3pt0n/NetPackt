/*!
    * Start Bootstrap - SB Admin v7.0.7 (https://startbootstrap.com/template/sb-admin)
    * Copyright 2013-2023 Start Bootstrap
    * Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-sb-admin/blob/master/LICENSE)
    */
    // 
// Scripts
// 

window.addEventListener('DOMContentLoaded', event => {

    // Toggle the side navigation
    const sidebarToggle = document.body.querySelector('#sidebarToggle');
    if (sidebarToggle) {
        // Uncomment Below to persist sidebar toggle between refreshes
        // if (localStorage.getItem('sb|sidebar-toggle') === 'true') {
        //     document.body.classList.toggle('sb-sidenav-toggled');
        // }
        sidebarToggle.addEventListener('click', event => {
            event.preventDefault();
            document.body.classList.toggle('sb-sidenav-toggled');
            localStorage.setItem('sb|sidebar-toggle', document.body.classList.contains('sb-sidenav-toggled'));
        });
    }

});


const data = {
    labels: ['Critical', 'High', 'Medium', 'Low', 'Informational'],
    datasets: [{
        label: 'My First Dataset',
        data: [6, 10, 8, 5, 19], //add data values from an analysis function
        backgroundColor: [
            'red',
            'orange',
            'yellow', 
            'green', 
            'white'
        ],
        hoverOffset: 4
    }]
};

// Get the canvas element
const ctx = document.getElementById('pieChart').getContext('2d');

// Create the pie chart
new Chart(ctx, {
    type: 'pie',
    data: data,
});

const rows = document.querySelectorAll('tbody tr');
rows.forEach(row => {
    const cell = row.querySelector('td:nth-child(4)');
    const value = cell.textContent.trim().toLowerCase();
    switch (value) {
        case 'severe':
            row.style.backgroundColor = '#ffcccc'; // Light red
            break;
        case 'high':
            row.style.backgroundColor = '#ffe0b3'; // Light orange
            break;
        case 'medium':
            row.style.backgroundColor = '#ffffcc'; // Light yellow
            break;
        case 'low':
            row.style.backgroundColor = '#ccffcc'; // Light green
            break;
        default:
            // Handle unknown or default case
            break;
    }
});
