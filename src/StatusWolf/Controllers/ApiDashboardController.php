<?php
/**
 * ApiController
 *
 * Describe your class here
 *
 * Author: Mark Troyer <disco@box.com>
 * Date Created: 3 March 2014
 *
 */

namespace StatusWolf\Controllers;

use PDO;
use Silex\Application;
use Silex\ControllerProviderInterface;
use StatusWolf\Security\User\SWUser;
use Symfony\Component\HttpFoundation\Request;

class ApiDashboardController implements ControllerProviderInterface {

    public function connect(Application $sw) {
        $controllers = $sw['controllers_factory'];

        $controllers->get('/saved/{user_id}', function(Application $sw, Request $request, $user_id) {
            $_saved_dashboards = array();

            $sql = "SELECT * FROM saved_dashboards WHERE user_id = ? AND shared = 0";
            $dashboard_query = $sw['db']->prepare($sql);
            $dashboard_query->bindValue(1, $user_id);
            $dashboard_query->execute();
            $_saved_dashboards['user_dashboards'] = array();
            while($user_dashboards = $dashboard_query->fetch()) {
                array_push($_saved_dashboards['user_dashboards'], array('id' => $user_dashboards['id'], 'title' => $user_dashboards['title']));
            }
            $sql = "SELECT dr.count, sd.*, u.username FROM dashboard_rank dr, saved_dashboards sd, users u WHERE sd.id=dr.id AND sd.user_id=u.id AND sd.shared=1 ORDER BY dr.count DESC";
            $shared_dashboard_query = $sw['db']->prepare($sql);
            $shared_dashboard_query->execute();
            $_saved_dashboards['shared_dashboards'] = array();
            while($shared_dashboards = $shared_dashboard_query->fetch()) {
                array_push($_saved_dashboards['shared_dashboards'], array('id' => $shared_dashboards['id'], 'user_id' => $shared_dashboards['user_id'], 'username' => $shared_dashboards['username'], 'title' => $shared_dashboards['title']));
            }
            return $sw->json($_saved_dashboards);
        })->bind('get_saved_dashboards');

        $controllers->get('/config/{dashboard_id}', function(Application $sw, $dashboard_id) {
            $dashboard_config = array();
            $user_token = $sw['security']->getToken();
            $user = $user_token->getUser();
            $user_id = $user instanceof SWUser ? $user->getId() : '0';
            $sql = "SELECT * FROM saved_dashboards WHERE id = ?";
            $dashboard_query = $sw['db']->prepare($sql);
            $dashboard_query->bindValue(1, $dashboard_id);
            $dashboard_query->execute();
            if (!$dashboard_data = $dashboard_query->fetch(PDO::FETCH_ASSOC)) {
                $dashboard_config['error'] = 'Not Found';
            } elseif ($dashboard_data['shared'] === 0 && $user_id !== $dashboard_data['user_id']) {
                $dashboard_config['error'] = 'Not Allowed';
            } else {
                $dashboard_config = $dashboard_data;
                $dashboard_config['widgets'] = unserialize($dashboard_data['widgets']);
                $sql = "UPDATE dashboard_rank SET count = count+1 WHERE id = ?";
                $rank_query = $sw['db']->prepare($sql);
                $rank_query->bindValue(1, $dashboard_id);
                $rank_query->execute();
            }
            return $sw->json($dashboard_config);
        })->bind('get_dashboard_config');

        return $controllers;
    }
}
