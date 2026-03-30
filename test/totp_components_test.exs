# SPDX-FileCopyrightText: 2024 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.TotpComponentsTest do
  @moduledoc false

  use ExUnit.Case, async: false
  alias AshAuthentication.Phoenix.Components.Totp.Verify2faForm
  alias AshAuthentication.Phoenix.TotpHelpers
  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  @endpoint AshAuthentication.Phoenix.Test.Endpoint

  setup do
    {:ok, conn: Phoenix.ConnTest.build_conn()}
  end

  describe "TOTP sign-in form" do
    test "renders TOTP sign-in form on sign-in page", %{conn: conn} do
      conn = get(conn, "/sign-in")
      assert {:ok, _view, html} = live(conn)

      assert html =~ "user-totp-sign-in-with-totp"
      assert html =~ "email"
      assert html =~ "code"
    end

    test "renders identity field for TOTP sign-in", %{conn: conn} do
      conn = get(conn, "/sign-in")
      assert {:ok, view, _html} = live(conn)

      assert has_element?(view, "#user-totp-sign-in-with-totp_email")
    end

    test "renders code field for TOTP sign-in", %{conn: conn} do
      conn = get(conn, "/sign-in")
      assert {:ok, view, _html} = live(conn)

      assert has_element?(view, "#user-totp-sign-in-with-totp_code")
    end

    test "validates form on change", %{conn: conn} do
      conn = get(conn, "/sign-in")
      assert {:ok, view, _html} = live(conn)

      view
      |> form("#user-totp-sign-in-with-totp", %{
        "user" => %{"email" => "test@example.com", "code" => "123456"}
      })
      |> render_change()

      assert has_element?(view, "#user-totp-sign-in-with-totp")
    end

    test "TOTP sign-in form has correct action URL", %{conn: conn} do
      conn = get(conn, "/sign-in")
      assert {:ok, _view, html} = live(conn)

      assert html =~ ~s(action="/auth/user/totp/sign_in")
    end

    test "TOTP sign-in form validates and submits", %{conn: conn} do
      conn = get(conn, "/sign-in")
      assert {:ok, view, _html} = live(conn)

      view
      |> form("#user-totp-sign-in-with-totp", %{
        "user" => %{
          "email" => "test@example.com",
          "code" => "123456"
        }
      })
      |> render_submit()

      # Form should still render (not crash) even with invalid credentials
      assert has_element?(view, "#user-totp-sign-in-with-totp")
    end
  end

  describe "TOTP setup form" do
    test "does NOT render setup form on sign-in page by default", %{conn: conn} do
      # Setup form should be on a dedicated page for authenticated users, not on sign-in page
      conn = get(conn, "/sign-in")
      assert {:ok, _view, html} = live(conn)

      refute html =~ "user-totp-setup-with-totp-wrapper"
    end

    test "does NOT show setup toggle on sign-in page by default", %{conn: conn} do
      conn = get(conn, "/sign-in")
      assert {:ok, _view, html} = live(conn)

      refute html =~ "Need to set up authenticator?"
    end
  end

  describe "TOTP verify form" do
    test "step-up submission includes current_user during validation", %{conn: _conn} do
      user = create_user()
      user_with_totp = setup_totp_for_user(user)
      code = NimbleTOTP.verification_code(user_with_totp.totp_secret)
      strategy = get_totp_strategy()

      {:ok, socket} =
        Verify2faForm.update(
          %{
            auth_routes_prefix: "/auth",
            current_user: user_with_totp,
            id: "totp_verify",
            mode: :step_up,
            resource: Example.Accounts.User,
            strategy: strategy
          },
          %Phoenix.LiveView.Socket{}
        )

      {:noreply, socket} =
        Verify2faForm.handle_event(
          "submit",
          %{"user" => %{"code" => code}},
          socket
        )

      assert socket.assigns.trigger_action
      assert socket.assigns.form.valid?
    end
  end

  defp create_user do
    Example.Accounts.User
    |> Ash.Changeset.for_create(:register_with_password, %{
      email: "totp-components-#{System.unique_integer()}@example.com",
      password: "password123!",
      password_confirmation: "password123!"
    })
    |> Ash.create!()
  end

  defp setup_totp_for_user(user) do
    {:ok, user_with_setup} =
      AshAuthentication.Strategy.action(
        get_totp_strategy(),
        :setup,
        %{user: user},
        []
      )

    setup_token = Ash.Resource.get_metadata(user_with_setup, :setup_token)
    totp_url = Ash.Resource.get_metadata(user_with_setup, :totp_url)
    %URI{query: query} = URI.parse(totp_url)
    %{"secret" => encoded_secret} = URI.decode_query(query)
    secret = Base.decode32!(encoded_secret, padding: false)
    code = NimbleTOTP.verification_code(secret)

    {:ok, confirmed_user} =
      AshAuthentication.Strategy.action(
        get_totp_strategy(),
        :confirm_setup,
        %{user: user_with_setup, setup_token: setup_token, code: code},
        []
      )

    confirmed_user
  end

  defp get_totp_strategy do
    {:ok, strategy} = TotpHelpers.get_totp_strategy(Example.Accounts.User)
    strategy
  end
end
