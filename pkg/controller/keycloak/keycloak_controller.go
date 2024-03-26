package keycloak

import (
    "context"
    "github.com/Nerzal/gocloak/v11"
    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    // other imports
)

// other functions

func (r *ReconcileKeycloak) getCACertificate(ctx context.Context, keycloak *v1.Keycloak) ([]byte, error) {
    if keycloak.Spec.CACertificateRef == nil {
        return nil, nil
    }

    var caCert []byte
    var err error

    switch keycloak.Spec.CACertificateRef.Kind {
    case "Secret":
        var secret corev1.Secret
        err = r.client.Get(ctx, types.NamespacedName{Name: keycloak.Spec.CACertificateRef.Name, Namespace: keycloak.Namespace}, &secret)
        if err != nil {
            return nil, err
        }
        caCert = secret.Data[keycloak.Spec.CACertificateRef.Key]
    case "ConfigMap":
        var configMap corev1.ConfigMap
        err = r.client.Get(ctx, types.NamespacedName{Name: keycloak.Spec.CACertificateRef.Name, Namespace: keycloak.Namespace}, &configMap)
        if err != nil {
            return nil, err
        }
        caCert = []byte(configMap.Data[keycloak.Spec.CACertificateRef.Key])
    default:
        return nil, fmt.Errorf("unsupported CACertificateRef kind '%s'", keycloak.Spec.CACertificateRef.Kind)
    }

    return caCert, nil
}

// other functions
