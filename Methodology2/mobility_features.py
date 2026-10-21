
import csv
from collections import defaultdict

data = defaultdict(list)

with open("mobility_data.csv", newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:
        time = float(row["time"])
        data[time].append({
            "id": row["vehicle_id"],
            "speed": float(row["speed"]),
            "x": float(row["x"]),
            "y": float(row["y"])
        })

with open("mobility_features.csv", "w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow([
        "time", "vehicle_count", "average_speed",
        "minimum_speed", "maximum_speed",
        "x_min", "x_max", "y_min", "y_max"
    ])

    for time in sorted(data):
        vehicles = data[time]
        speeds = [v["speed"] for v in vehicles]
        xs = [v["x"] for v in vehicles]
        ys = [v["y"] for v in vehicles]

        writer.writerow([
            time,
            len(set(v["id"] for v in vehicles)),
            round(sum(speeds) / len(speeds), 2),
            min(speeds),
            max(speeds),
            min(xs),
            max(xs),
            min(ys),
            max(ys)
        ])

print("Mobility feature extraction completed")
print("Output saved to mobility_features.csv")
