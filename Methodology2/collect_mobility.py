import traci
import csv

traci.start(["sumo", "-n", "network.net.xml", "-r", "routes.rou.xml"])

with open("mobility_data.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["time", "vehicle_id", "speed", "x", "y"])

    while traci.simulation.getMinExpectedNumber() > 0:
        traci.simulationStep()

        time = traci.simulation.getTime()

        for vehicle_id in traci.vehicle.getIDList():
            speed = traci.vehicle.getSpeed(vehicle_id)
            x, y = traci.vehicle.getPosition(vehicle_id)

            writer.writerow([
                time,
                vehicle_id,
                round(speed, 2),
                round(x, 2),
                round(y, 2)
            ])

traci.close()

print("Mobility data saved to mobility_data.csv")
