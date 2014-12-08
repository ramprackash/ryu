var url = "http://" + location.hostname + ":8080";

function updatePerf() {
    var lpPerfBody = document.getElementById('paper-container-ids-lp-perf');
    while (lpPerfBody.firstChild) {
            lpPerfBody.removeChild(lpPerfBody.firstChild);
    }
    var text = "";
    $.get(url.concat("/ids/lightperf"), function(resp){
          lpPerfBody.innerHTML = resp;
//        var lines = resp.split("\n");
//        for (line in lines){
//            var new_p = document.createElement('FONT');
//            new_p.appendChild(document.createTextNode(lines[line]));
//            portScanBody.appendChild(new_p);
//            portScanBody.appendChild(document.createElement('BR'));
//        }
    });
    
}

updatePerf();

var perfIntervalID = setInterval(function(){updatePerf()}, 5000);

function stopPerfRefresh() {
    clearInterval(perfIntervalID);
}
