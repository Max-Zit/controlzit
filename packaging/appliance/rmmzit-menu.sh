# RMMZit appliance: the setup menu starts when rzadmin (czadmin on
# appliances from before the rename to RMMZit) signs in on the server's own
# screen (not over SSH). Leave it for a command line; open it
# again with: sudo rmmzit-setup
case "$(tty 2>/dev/null)" in
/dev/tty[0-9]*)
    case "$(id -un)" in rzadmin|czadmin) is_admin=1 ;; *) is_admin= ;; esac
    if [ -n "$is_admin" ] && [ -z "${RZ_MENU_SHOWN:-}" ]; then
        export RZ_MENU_SHOWN=1
        sudo -n /usr/local/sbin/rmmzit-setup
    fi
    ;;
esac
