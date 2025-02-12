use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::{
    future::{ok, Ready},
    FutureExt,
};
use std::{
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use super::jwt::verify_jwt;

pub struct JwtMiddleware {
    required_role: Option<String>,
}

impl JwtMiddleware {
    pub fn new(required_role: Option<String>) -> Self {
        Self { required_role }
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Transform = JwtMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtMiddlewareService {
            service: Rc::new(service),
            required_role: self.required_role.clone(),
        })
    }
}

pub struct JwtMiddlewareService<S> {
    service: Rc<S>,
    required_role: Option<String>,
}

impl<S, B> Service<ServiceRequest> for JwtMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let headers = req.headers().clone();
        let required_role = self.required_role.clone();

        async move {
            let token = headers
                .get("Authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(String::from);

            if let Some(token) = token {
                if let Ok(claims) = verify_jwt(&token) {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as usize;
                    if claims.exp < now {
                        return Ok(req.into_response(
                            HttpResponse::Unauthorized()
                                .body("Unauthorized: Token has expired")
                                .map_into_boxed_body(),
                        ));
                    }

                    if let Some(ref role) = required_role {
                        if claims.role != *role {
                            return Ok(req.into_response(
                                HttpResponse::Forbidden()
                                    .body("Forbidden: Insufficient permissions")
                                    .map_into_boxed_body(),
                            ));
                        }
                    }

                    req.extensions_mut().insert(claims);
                    return service.call(req).await.map(|res| res.map_into_boxed_body());
                }
            }

            Ok(req.into_response(
                HttpResponse::Unauthorized()
                    .body("Unauthorized: Invalid token")
                    .map_into_boxed_body(),
            ))
        }
        .boxed_local()
    }
}
