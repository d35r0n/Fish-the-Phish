// const request = new XMLHttpRequest();

// const url = btoa(window.location.href);
// const api = "http://127.0.0.1:5000/fisher/";

// function updateIcon(progress) {
//     if (progress == 0) {
//         browser.browserAction.setIcon({
//             path: {
//                 48: "icons/yellow.svg",
//                 96: "icons/yellow.svg"
//             }
//         })
//     } else if (progress == 1) {
//         browser.browserAction.setIcon({
//             path: {
//                 48: "icons/red.svg",
//                 96: "icons/red.svg"
//             }
//         })
//     } else if (progress == 2) {
//         browser.browserAction.setIcon({
//             path: {
//                 48: "icons/green.svg",
//                 96: "icons/green.svg"
//             }
//         })
//     }
// }

// console.log(api+url)

// request.open("GET", api+url);
// request.send();
// updateIcon(0)

// request.onload = (e) => {
//     const response = JSON.parse(request.response);
//     if (response.safe == "Safe") {
//         updateIcon(2);
//     } else {
//         updateIcon(1);
//     }
//     console.log(response.url);
//     console.log(response.safe);
//     console.log(response.score);
// }

// request.onerror = function() {
//     console.log("API appears to be Offline")
// }