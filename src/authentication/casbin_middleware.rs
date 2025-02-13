use super::jwt::verify_jwt;
use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use casbin::{CoreApi, Enforcer};
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

pub struct JwtCasbinMiddleware {
    required_role: Option<String>,
    enforcer: Rc<Enforcer>,
}

impl JwtCasbinMiddleware {
    pub fn new(required_role: Option<String>, enforcer: Enforcer) -> Self {
        Self {
            required_role,
            enforcer: Rc::new(enforcer),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwtCasbinMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Transform = JwtCasbinMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtCasbinMiddlewareService {
            service: Rc::new(service),
            required_role: self.required_role.clone(),
            enforcer: self.enforcer.clone(),
        })
    }
}

pub struct JwtCasbinMiddlewareService<S> {
    service: Rc<S>,
    required_role: Option<String>,
    enforcer: Rc<Enforcer>,
}

impl<S, B> Service<ServiceRequest> for JwtCasbinMiddlewareService<S>
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
        let enforcer = self.enforcer.clone();

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

                    let sub = claims.role.clone();
                    let obj = req.path().to_string();
                    let act = req.method().to_string();

                    let authorized = enforcer.enforce((sub, obj, act)).unwrap_or(false);

                    if !authorized {
                        return Ok(req.into_response(
                            HttpResponse::Forbidden()
                                .body("Forbidden: Insufficient permissions")
                                .map_into_boxed_body(),
                        ));
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
