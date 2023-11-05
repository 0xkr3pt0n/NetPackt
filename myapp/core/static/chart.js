function drawchart(data){// Set new default font family and font color to mimic Bootstrap's default styling
    Chart.defaults.global.defaultFontFamily = '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
    Chart.defaults.global.defaultFontColor = '#292b2c';
    
    // Pie Chart Example
    var ctx = document.getElementById("myPieChart");
    var myPieChart = new Chart(ctx, {
      type: 'pie',
      data: {
        labels: ["None", "HIGH", "MEDUIM", "Low"],
        datasets: [{
          data: data,
          backgroundColor: ['#007bff', '#dc3545', '#ffc107', '#f8d7da'],
        }],
      },
    });
    }