use geo::algorithm::haversine_distance::HaversineDistance;
use geo_types::Point;
use geoconvert::{LatLon, Mgrs};
use geomorph::coord::Coord;

pub struct Geofence {
    target_coord: LatLon,
    target_radius: f64,
    pub mgrs: bool,
}

impl Geofence {
    pub fn new(target_grid: String, target_radius: f64) -> Result<Geofence, String> {
        let mut mgrs = false;
        let coord = if is_mgrs(target_grid.clone()) {
            let mgrs_string = Mgrs::parse_str(&target_grid).unwrap();
            mgrs = true;
            LatLon::from_mgrs(&mgrs_string)
        } else {
            let parts: Vec<&str> = target_grid.split(',').collect();
            if parts.len() != 2 {
                return Err("Input should be in 'lat,lng' format".to_string());
            }
            let latitude = parts[0].parse::<f64>().map_err(|_| "Invalid latitude")?;
            let longitude = parts[1].parse::<f64>().map_err(|_| "Invalid longitude")?;
            LatLon::create(latitude, longitude).map_err(|_| "Invalid coordinates")?
        };
        Ok(Geofence {
            target_coord: coord,
            target_radius,
            mgrs,
        })
    }

    pub fn distance_to_target(&self, current_point: (f64, f64)) -> f64 {
        let current_coord_latlon = LatLon::create(current_point.0, current_point.1).unwrap();
        self.target_coord.haversine(&current_coord_latlon)
    }

    pub fn is_within_area(&self, current_point: (f64, f64)) -> bool {
        let current_coord = Coord::new(current_point.0, current_point.1);
        let target_point = Point::new(self.target_coord.longitude(), self.target_coord.latitude());
        let current_point = Point::new(current_coord.lon, current_coord.lat);
        current_point.haversine_distance(&target_point) <= self.target_radius
    }
}

pub fn is_mgrs(grid: String) -> bool {
    Mgrs::parse_str(&grid).is_ok()
}
