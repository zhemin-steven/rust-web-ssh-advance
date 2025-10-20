use warp::{Filter, Reply};
use warp::http::StatusCode;
use std::convert::Infallible;

pub fn route_404() -> impl Filter<Extract = impl Reply, Error = Infallible> + Clone {
    warp::any().map(|| {
        warp::reply::with_status(
            warp::reply::html(include_str!("../../static/404.html")),
            StatusCode::NOT_FOUND,
        )
    })
}

