import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";
import "bootstrap-icons/font/bootstrap-icons.css";
import { site_routes } from "./routes";

createRoot(document.getElementById("root")!).render(
    <StrictMode>
        <Router>
            <Routes>
                {site_routes.map((route, index) => (
                    <Route key={index} path={route.path} element={route.element} index={route.index}>
                        {route.children?.map((child, childIndex) => (
                            <Route key={`${index}-${childIndex}`} path={child.path} element={child.element} index={child.index} />
                        ))}
                    </Route>
                ))}
            </Routes>
        </Router>
    </StrictMode>
);
