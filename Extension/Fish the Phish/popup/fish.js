const request = new XMLHttpRequest();

function getActiveTab() {
    return browser.tabs.query({active: true, currentWindow: true});
}

let api = "http://127.0.0.1:5000/fisher/";

getActiveTab().then((tabs) => {
    url = btoa(tabs[0].url);
    request.open("GET", api+url);
    request.send();
    document.getElementById("url").innerHTML = tabs[0].url;
    request.onload = (e) => {
        const response = JSON.parse(request.response);
        document.getElementById("safe").innerHTML = response.safe;
        document.getElementById("score").innerHTML = response.score;
    }
})

// let tabs = await getActiveTab();
// let url = btoa(tabs[0].url);

// request.open("GET", api+url);
// request.send();

// request.onload = (e) => {
//     const response = JSON.parse(request.response);
//     // document.getElementById("url").innerHTML = response.url;
//     document.getElementById("safe").innerHTML = response.safe;
//     document.getElementById("score").innerHTML = response.score;
// }