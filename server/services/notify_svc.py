"""
Warden — In-app notification service
Writes to endpt.notifications for real-time dashboard badges.
"""


def push(conn, *, admin_id, type_: str, title: str, body: str = None,
         link: str = None, ref_id=None, company_id=None):
    """Insert a notification for a specific admin user."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO endpt.notifications
              (admin_id, company_id, type, title, body, link, ref_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                str(admin_id),
                str(company_id) if company_id else None,
                type_,
                title,
                body,
                link,
                str(ref_id) if ref_id else None,
            ),
        )
    conn.commit()


def push_to_company_admins(conn, *, company_id, type_: str, title: str,
                           body: str = None, link: str = None, ref_id=None):
    """Push a notification to all company_admin and branch_admin users in a company."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id FROM endpt.admin_users
            WHERE company_id = %s AND is_active = true
              AND role IN ('company_admin', 'branch_admin')
            """,
            (str(company_id),),
        )
        admins = cur.fetchall()

    for (admin_id,) in admins:
        push(conn, admin_id=admin_id, type_=type_, title=title,
             body=body, link=link, ref_id=ref_id, company_id=company_id)


def mark_read(conn, notification_id, admin_id):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE endpt.notifications SET is_read = true WHERE id = %s AND admin_id = %s",
            (str(notification_id), str(admin_id)),
        )
    conn.commit()


def unread_count(conn, admin_id) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM endpt.notifications WHERE admin_id = %s AND is_read = false",
            (str(admin_id),),
        )
        row = cur.fetchone()
        return row[0] if row else 0
