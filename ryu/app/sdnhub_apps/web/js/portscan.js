var url = "http://" + location.hostname + ":8080";

function updatePortScanReport() {
    var portScanBody = document.getElementById('paper-container-ids-portscan');
    while (portScanBody.firstChild) {
            portScanBody.removeChild(portScanBody.firstChild);
    }
    var text = "";
    $.get(url.concat("/ids/portscan"), function(resp){
//          portScanBody.innerHTML = resp;
        var lines = resp.split("\n");
        for (line in lines){
            var new_p = document.createElement('FONT');
            new_p.appendChild(document.createTextNode(lines[line]));
            portScanBody.appendChild(new_p);
            portScanBody.appendChild(document.createElement('BR'));
        }
    });
    
}

updatePortScanReport();

var portScanIntervalID = setInterval(function(){updatePortScanReport()}, 5000);

function stopPortScanRefresh() {
    clearInterval(portScanIntervalID);
}
