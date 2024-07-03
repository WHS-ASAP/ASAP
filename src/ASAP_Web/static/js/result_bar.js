// static/js/result_bar.js

document.addEventListener("DOMContentLoaded", function () {
  // Fetch data from the API
  fetch("/api/vulnerability-counts")
    .then((response) => response.json())
    .then((data) => {
      // Prepare data for the bar chart
      const labels = data.packages;
      const counts = data.counts;

      // Combine labels and counts into an array of objects
      const combinedData = labels.map((label, index) => ({
        label: label,
        count: counts[index],
      }));

      // Sort the combined data based on counts in descending order
      combinedData.sort((a, b) => b.count - a.count);

      // Extract sorted labels and counts
      const sortedLabels = combinedData.map((item) => item.label);
      const sortedCounts = combinedData.map((item) => item.count);

      // Generate gradient colors from light green to dark green
      const maxCount = Math.max(...sortedCounts);
      const minCount = Math.min(...sortedCounts);
      const colors = sortedCounts.map((count) => {
        const intensity = (count - minCount) / (maxCount - minCount);
        const greenValue = Math.floor(255 - 100 * intensity);
        return `rgba(0, ${greenValue}, 0, 1)`; // Green gradient color
      });

      // Bar chart data and options
      const barChartData = {
        labels: sortedLabels,
        datasets: [
          {
            label: "# of Findings",
            data: sortedCounts,
            backgroundColor: colors,
            borderColor: colors,
            borderWidth: 1,
            barThickness: 30, // Adjust the bar thickness as needed
            borderRadius: {
              topRight: 12,
              bottomRight: 12,
            }, // Apply radius to the right side
          },
        ],
      };

      const barChartOptions = {
        indexAxis: "y", // Make the chart horizontal
        scales: {
          x: {
            beginAtZero: true,
            ticks: {
              color: "#014a17", // Color for x-axis labels
              font: {
                family: "verdana, fantasy", // Font for x-axis labels
              },
            },
            title: {
              color: "#014a17", // Color for x-axis title (if any)
              font: {
                family: "verdana, fantasy", // Font for x-axis labels
              },
            },
          },
          y: {
            ticks: {
              color: "#014a17", // Color for y-axis labels
              font: {
                family: "verdana, fantasy", // Font for x-axis labels
              },
            },
            title: {
              color: "#014a17", // Color for y-axis title (if any)
              font: {
                family: "verdana, fantasy", // Font for x-axis labels
              },
            },
          },
        },
        plugins: {
          legend: {
            labels: {
              color: "#014a17", // Color for legend labels
              font: {
                family: "verdana, fantasy", // Font for x-axis labels
              },
            },
          },
        },
      };

      // Get context with jQuery - using jQuery's .get() method.
      if (document.getElementById("barChart")) {
        const barChartCanvas = document.getElementById("barChart").getContext("2d");
        // Create the bar chart
        new Chart(barChartCanvas, {
          type: "bar",
          data: barChartData,
          options: barChartOptions,
        });
      }
    })
    .catch((error) => console.error("Error fetching data:", error));
});
