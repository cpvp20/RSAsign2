let list_element_in_html = document.getElementById('files');

fetch('/files')
  .then(response => response.json())
  .then(data => displayFiles(data.files));

  
function displayFiles(files){
  for(file of files){
    let li = document.createElement("li");
    li.appendChild(document.createTextNode(file));
    list_element_in_html.appendChild(li);
  }
}
