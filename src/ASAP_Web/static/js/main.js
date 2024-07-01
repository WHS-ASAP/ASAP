document.addEventListener("DOMContentLoaded", function () {
  fetch("/api/vulnerability-counts")
    .then((response) => response.json())
    .then((data) => {
      const ctx = document.getElementById("vulnerabilityChart").getContext("2d");
      new Chart(ctx, {
        type: "bar",
        data: {
          labels: data.packages,
          datasets: [
            {
              label: "Vulnerability Counts",
              data: data.counts,
              backgroundColor: "rgba(75, 192, 192, 0.2)",
              borderColor: "rgba(75, 192, 192, 1)",
              borderWidth: 1,
            },
          ],
        },
        options: {
          scales: {
            y: {
              beginAtZero: true,
            },
          },
        },
      });
    });
});
