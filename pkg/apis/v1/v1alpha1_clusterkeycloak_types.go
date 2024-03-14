package v1alpha1

type ClusterKeycloakSpec struct {
    // ...
    // Fields before caCertificateRef

    // caCertificateRef allows specifying a reference to a Secret or ConfigMap containing the custom CA certificate
    // The 'key' specifies the data key within the Secret or ConfigMap that contains the CA certificate
    CACertificateRef CACertificateReference `json:"caCertificateRef,omitempty"`
}

type CACertificateReference struct {
    // Kind is the type of the resource to refer either 'Secret' or 'ConfigMap'
    Kind string `json:"kind"`
    // Name is the name of the resource
    Name string `json:"name"`
    // Key is the key inside the resource data which contains the CA certificate
    Key string `json:"key"`
    // ...
}

// ...
