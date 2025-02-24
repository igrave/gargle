% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/credentials_byo_oauth2.R
\name{credentials_byo_oauth2}
\alias{credentials_byo_oauth2}
\title{Load a user-provided token}
\usage{
credentials_byo_oauth2(scopes = NULL, token, ...)
}
\arguments{
\item{scopes}{A character vector of scopes to request. Pick from those listed
at \url{https://developers.google.com/identity/protocols/oauth2/scopes}.

For certain token flows, the
\code{"https://www.googleapis.com/auth/userinfo.email"} scope is unconditionally
included. This grants permission to retrieve the email address associated
with a token; gargle uses this to index cached OAuth tokens. This grants no
permission to view or send email and is generally considered a low-value
scope.}

\item{token}{A token with class \link[httr:Token-class]{Token2.0} or an object of
httr's class \code{request}, i.e. a token that has been prepared with
\code{\link[httr:config]{httr::config()}} and has a \link[httr:Token-class]{Token2.0} in the
\code{auth_token} component.}

\item{...}{Additional arguments passed to all credential functions.}
}
\value{
An \link[httr:Token-class]{Token2.0}.
}
\description{
This function is designed to pass its \code{token} input through, after doing a
few checks and some light processing:
\itemize{
\item If \code{token} has class \code{request}, i.e. it is a token that has been prepared
with \code{\link[httr:config]{httr::config()}}, the \code{auth_token} component is extracted. For
example, such input could be returned by \code{googledrive::drive_token()}
or \code{bigrquery::bq_token()}.
\item If \code{token} is an instance of \code{Gargle2.0} (so: a gargle-obtained user
token), checks that it appears to be a Google OAuth token, based on its
embedded \code{oauth_endpoint}. Refreshes the token, if it's refreshable.
\item Returns the \code{token}.
}

There is no point in providing \code{scopes}. They are ignored because the
\code{scopes} associated with the token have already been baked in to the token
itself and gargle does not support incremental authorization. The main point
of \code{credentials_byo_oauth2()} is to allow \code{token_fetch()} (and packages that
wrap it) to accommodate a "bring your own token" workflow.

This also makes it possible to obtain a token with one package and then
register it for use with another package. For example, the default scope
requested by googledrive is also sufficient for operations available in
googlesheets4. You could use a shared token like so:

\if{html}{\out{<div class="sourceCode">}}\preformatted{library(googledrive)
library(googlesheets4)
drive_auth(email = "jane_doe@example.com")
gs4_auth(token = drive_token())
# work with both packages freely now, with the same identity
}\if{html}{\out{</div>}}
}
\examples{
\dontrun{
# assume `my_token` is a Token2.0 object returned by a function such as
# credentials_user_oauth2()
credentials_byo_oauth2(token = my_token)
}
}
\seealso{
Other credential functions: 
\code{\link{credentials_app_default}()},
\code{\link{credentials_external_account}()},
\code{\link{credentials_gce}()},
\code{\link{credentials_github_actions}()},
\code{\link{credentials_service_account}()},
\code{\link{credentials_user_oauth2}()},
\code{\link{token_fetch}()}
}
\concept{credential functions}
