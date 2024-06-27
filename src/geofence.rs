use geo::algorithm::haversine_distance::HaversineDistance;
use geo_types::Point;
use geoconvert::{LatLon, Mgrs};
use geomorph::coord::Coord;

pub struct Geofence {
    target_coord: LatLon,
    target_radius: f64,
}

impl Geofence {
    pub fn new(target_grid: String, target_radius: f64) -> Geofence {
        let mgrs_string = Mgrs::parse_str(&target_grid).unwrap();
        let target_coord_latlon = LatLon::from_mgrs(&mgrs_string);
        Geofence {
            target_coord: target_coord_latlon,
            target_radius: target_radius,
        }
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
