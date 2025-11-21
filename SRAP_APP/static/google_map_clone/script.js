mapboxgl.accessToken = "pk.eyJ1Ijoic3ViaGFtcHJlZXQiLCJhIjoiY2toY2IwejF1MDdodzJxbWRuZHAweDV6aiJ9.Ys8MP5kVTk5P9V2TDvnuDg";

navigator.geolocation.getCurrentPosition(successLocation, errorLocation, { enableHighAccuracy: true });

function successLocation(position) {
    const userCoords = [position.coords.longitude, position.coords.latitude];
    setupMap(userCoords);
    fetchNearbyPOIs(userCoords);
}

function errorLocation() {
    const fallbackCoords = [-2.24, 53.48];
    setupMap(fallbackCoords);
}

let map, directions;

function setupMap(center) {
    map = new mapboxgl.Map({
        container: "map",
        style: "mapbox://styles/mapbox/streets-v11",
        center: center,
        zoom: 15
    });

    map.addControl(new mapboxgl.NavigationControl());

    directions = new MapboxDirections({ accessToken: mapboxgl.accessToken });
    map.addControl(directions, "top-left");

    new mapboxgl.Marker({ color: "red" })
        .setLngLat(center)
        .setPopup(new mapboxgl.Popup().setText("You are here"))
        .addTo(map);
}

async function fetchNearbyPOIs(center) {
    const [lng, lat] = center;
    const delta = 0.01;
    const south = lat - delta, north = lat + delta;
    const west = lng - delta, east = lng + delta;

    const query = `
    [out:json][timeout:25];
    (
      node["amenity"~"restaurant|cafe|fast_food|pub"](${south},${west},${north},${east});
      node["shop"](${south},${west},${north},${east});
      node["leisure"~"park|garden"](${south},${west},${north},${east});
      node["amenity"~"bus_station|parking|bicycle_rental"](${south},${west},${north},${east});
    );
    out center;
    `;

    try {
        const response = await fetch("https://overpass-api.de/api/interpreter", {
            method: "POST",
            body: new URLSearchParams({ data: query })
        });
        const data = await response.json();

        data.elements.forEach(place => {
            const name = place.tags.name || "Unknown";
            const type = place.tags.amenity || place.tags.shop || place.tags.leisure || "Unknown";
            const lat = place.lat;
            const lng = place.lon;

            const marker = new mapboxgl.Marker({ color: "blue" })
                .setLngLat([lng, lat])
                .setPopup(new mapboxgl.Popup().setHTML(`
                    <b>${name}</b><br>${type}<br>
                    <button onclick="setDestination(${lng},${lat})">Navigate Here</button>
                `))
                .addTo(map);
        });

    } catch (err) {
        console.error("Error fetching POIs:", err);
    }
}

function setDestination(lng, lat) {
    if (directions) {
        directions.setDestination([lng, lat]);
    }
}
