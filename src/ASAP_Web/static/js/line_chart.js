document.addEventListener("DOMContentLoaded", function () {
  fetch("/api/vulnerability-trend")
    .then((response) => response.json())
    .then((data) => {
      const packages = Object.keys(data);
      const vulnTypes = [...new Set(packages.flatMap((pkg) => Object.keys(data[pkg])))];

      const colors = [
        "#FFB3BA", // Pastel Red
        "#FFDFBA", // Pastel Orange
        "#FFFFBA", // Pastel Yellow
        "#BAFFC9", // Pastel Green
        "#BAE1FF", // Pastel Blue
        "#E0BAFF", // Pastel Indigo
        "#FFC3FF", // Pastel Violet
        "#FFB3FF", // Pastel Pink
        "#FFB347", // Pastel Apricot
        "#B3FFFF", // Pastel Cyan
      ];

      const datasets = packages.map((pkg, index) => ({
        label: pkg,
        data: vulnTypes.map((type) => data[pkg][type] || 0),
        borderColor: colors[index % colors.length],
        fill: false,
      }));

      const ctx = document.getElementById("lineChart").getContext("2d");
      new Chart(ctx, {
        type: "line",
        data: {
          labels: vulnTypes,
          datasets: datasets,
        },
        options: {
          responsive: true,
          maintainAspectRatio: false, // Ensure it respects the CSS max dimensions
          scales: {
            x: {
              title: {
                display: true,
                text: "Type",
              },
            },
            y: {
              title: {
                display: true,
                text: "Count",
              },
            },
          },
          plugins: {
            legend: {
              display: true,
              position: "top",
            },
          },
        },
      });
    });
});
