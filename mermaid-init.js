// Load mermaid from CDN with SRI verification
(function() {
    var script = document.createElement("script");
    script.src = "https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js";
    script.integrity = "sha384-rbtjAdnIQE/aQJGEgXrVUlMibdfTSa4PQju4HDhN3sR2PmaKFzhEafuePsl9H/9I";
    script.crossOrigin = "anonymous";
    script.onload = function() {
        // Find all mermaid code blocks (mdbook renders ```mermaid as <code class="language-mermaid">)
        document.querySelectorAll("code.language-mermaid").forEach(function(el) {
            var div = document.createElement("pre");
            div.className = "mermaid";
            div.textContent = el.textContent;
            el.parentElement.replaceWith(div);
        });
        mermaid.initialize({ startOnLoad: true });
    };
    document.head.appendChild(script);
})();
