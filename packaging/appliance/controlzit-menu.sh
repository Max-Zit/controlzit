# ControlZit appliance: the setup menu starts when czadmin signs in on the
# server's own screen (not over SSH). Leave it for a command line; open it
# again with: sudo controlzit-setup
case "$(tty 2>/dev/null)" in
/dev/tty[0-9]*)
    if [ "$(id -un)" = czadmin ] && [ -z "${CZ_MENU_SHOWN:-}" ]; then
        export CZ_MENU_SHOWN=1
        sudo -n /usr/local/sbin/controlzit-setup
    fi
    ;;
esac
