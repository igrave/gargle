#' Get a token using Github Actions
#'
#' @description

#' `r lifecycle::badge('experimental')`

#' Workload identity federation is a new (as of April 2021) keyless
#' authentication mechanism that allows applications running on a non-Google
#' Cloud platform, such as Github Actions, to access Google Cloud resources without using a
#' conventional service account token. This eliminates the need to
#' safely manage service account credential files.
#'

#'  Unlike service accounts, the configuration file for workload identity
#'  federation contains no secrets. Instead, it holds non-sensitive metadata.
#'  The external application obtains the needed sensitive data "on-the-fly" from
#'  the running instance. The combined data is then used to obtain a so-called
#'  subject token from the external identity provider, such as AWS. This is then
#'  sent to Google's Security Token Service API, in exchange for a very
#'  short-lived federated access token. Finally, the federated access token is
#'  sent to Google's Service Account Credentials API, in exchange for a
#'  short-lived GCP access token. This access token allows the external
#'  application to impersonate a service account and inherit the permissions of
#'  the service account to access GCP resources.

#'
#' @inheritParams token_fetch

#' @param project_id The google cloud project id
#' @param workload_identity_provider The workload identity provider
#' @param service_account The service account email address
#' @param lifetime Lifespan of token in seconds as a string `"300s"`
#' @param scopes Requested scopes for the access token
#'

#' @seealso There is some setup required in GCP to enable this auth flow.
#'   This function reimplements the `google-github-actions/auth`. The
#'   documentation for that workflow provides instructions on the setup steps.

#' * <https://github.com/google-github-actions/auth?tab=readme-ov-file#indirect-wif>

#' @return A [WifToken()] or `NULL`.
#' @family credential functions
#' @export
#' @examples
#' \dontrun{
#' credentials_github_actions()
#' }
credentials_github_actions <- function(project_id,
  workload_identity_provider,
  service_account,
  lifetime = "300s",
  scopes = "https://www.googleapis.com/auth/drive.file",
                                         ...) {
  gargle_debug("trying {.fun credentials_github_actions}")
  if (!detect_github_actions() || is.null(scopes)) {
    return(NULL)
  }

  scopes <- normalize_scopes(add_email_scope(scopes))

  token <- oauth_gha_token(
    project_id = project_id,
    workload_identity_provider = workload_identity_provider,
    service_account = service_account,
    lifetime = lifetime,
    scopes = scopes, 
    ...)

  if (is.null(token$credentials$access_token) ||
    !nzchar(token$credentials$access_token)) {
    NULL
  } else {
    gargle_debug("service account email: {.email {token_email(token)}}")
    token
  }
}

#' Generate OAuth token for an external account on Github Actions
#'
#' @inheritParams credentials_github_actions
#' @param universe Set the domain for the endpoints
#'
#' @keywords internal
#' @export
oauth_gha_token <- function(project_id,
                            workload_identity_provider,
                            service_account,
                            lifetime,
                            scopes = "https://www.googleapis.com/auth/drive.file",
                            universe = "googleapis.com",
                            id_token_url = Sys.getenv("ACTIONS_ID_TOKEN_REQUEST_URL"),
                            id_token_request_token = Sys.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")) {
  if (id_token_url == "" || id_token_request_token == "") {
    gargle_abort(paste0(
     "GitHub Actions did not inject $ACTIONS_ID_TOKEN_REQUEST_TOKEN or ",
     "$ACTIONS_ID_TOKEN_REQUEST_URL into this job. This most likely means the ",
     "GitHub Actions workflow permissions are incorrect, or this job is being ",
     "run from a fork. For more information, please see ",
     "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"))
  }

  endpoints <- c(
     iam = "https://iam.{universe}/v1",
     iamcredentials = "https://iamcredentials.{universe}/v1",
     oauth2 = "https://oauth2.{universe}",
     sts = "https://sts.{universe}/v1",
     www = "https://www.{universe}"
  )
  endpoints <- sub("{universe}", universe, endpoints, fixed = TRUE)
  
  params <- list(
    scopes = scopes,
    project_id = project_id,
    workload_identity_provider = workload_identity_provider,
    lifetime = lifetime,
    universe = universe,
    id_token_url = id_token_url,
    id_token_request_token = id_token_request_token,
    github_actions = TRUE,
    endpoints = endpoints,
    service_account = service_account,
    token_url = paste0(endpoints[["sts"]], "/token"),
    audience = paste0("//", httr::parse_url(endpoints[["iam"]])$hostname, "/", workload_identity_provider),
    oidc_token_audience = paste0("https://iam.googleapis.com/", workload_identity_provider),
    subject_token_type = "urn:ietf:params:oauth:token-type:jwt",
    impersonation_url = paste0(endpoints[["iamcredentials"]], "/projects/-/serviceAccounts/", service_account,":generateAccessToken"),
    # the most pragmatic way to get super$sign() to work
    # can't implement my own method without needing unexported httr functions
    # request() or build_request()
    as_header = TRUE
  )
  WifToken$new(params = params)
}


detect_github_actions <- function() {
  if (Sys.getenv("GITHUB_ACTIONS") == "true") {
    return(TRUE)
  }
  gargle_debug("
    Environment variable GITHUB_ACTIONS is not 'true'")
  FALSE
}

init_oauth_external_account <- function(params) {
  if (params$github_actions) {
    serialized_subject_token <- gha_subject_token(params)
  } else {
    credential_source <- params$credential_source
    if (!identical(credential_source$environment_id, "aws1")) {
      gargle_abort("
       {.pkg gargle}'s workload identity federation flow only supports AWS at \\
       this time.")
    }
    subject_token <- aws_subject_token(
     credential_source = credential_source,
     audience = params$audience
    )
    serialized_subject_token <- serialize_subject_token(subject_token)
  }


  federated_access_token <- fetch_federated_access_token(
    params = params,
    subject_token = serialized_subject_token
  )

  fetch_wif_access_token(
    federated_access_token,
    impersonation_url = params[["service_account_impersonation_url"]],
    scope = params[["scope"]]
  )
}


gha_subject_token <- function(params) {

  req <- list(
    method = "GET",
    url = params$id_token_url,
    query = list(audience = params[["oidc_token_audience"]]),
    token = httr::add_headers(
      Authorization = paste("Bearer", params$id_token_request_token)
    )  
  )
  
  resp <- request_make(req)
  response_process(resp)$value
}