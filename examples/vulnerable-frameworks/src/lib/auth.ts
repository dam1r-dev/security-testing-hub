// the login token is readable by any script on the page
export function saveLogin(jwt: string) {
  localStorage.setItem('token', jwt);
}
