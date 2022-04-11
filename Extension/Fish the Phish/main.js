const request = new XMLHttpRequest();

const url = btoa(window.location.href);
const api = "http://127.0.0.1:5000/fisher/";

console.log(api+url)

request.open("GET", api+url);
request.send();

request.onload = (e) => {
    const response = JSON.parse(request.response);
    console.log(response.url);
    console.log(response.safe);
    console.log(response.score);
}

request.onerror = function() {
    console.log("API appears to be Offline")
}